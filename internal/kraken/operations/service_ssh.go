package operations

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/creack/pty"
	gliderssh "github.com/gliderlabs/ssh"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
	gossh "golang.org/x/crypto/ssh"
)

type sshService struct {
	metadata ServiceMetadata
	server   *gliderssh.Server
	listener net.Listener
}

func NewSSH(config map[string]string) (Service, error) {
	port, err := servicePort(config)
	if err != nil {
		return nil, err
	}
	password := config["password"]
	authorizedKeyText := config["authorizedKey"]
	if password == "" && authorizedKeyText == "" {
		return nil, fmt.Errorf("SSH requires a password or authorized key")
	}
	signers, err := krakenSSHHostSigners()
	if err != nil {
		return nil, err
	}

	var authorizedKey gliderssh.PublicKey
	if authorizedKeyText != "" {
		var parseErr error
		authorizedKey, _, _, _, parseErr = gliderssh.ParseAuthorizedKey([]byte(authorizedKeyText))
		if parseErr != nil {
			return nil, fmt.Errorf("Key: %w", parseErr)
		}
	}

	username := config["username"]
	allowPty := config["allowPty"] != "false"
	server := &gliderssh.Server{
		Handler: handleKrakenSSHSession,
		PasswordHandler: func(ctx gliderssh.Context, supplied string) bool {
			if username != "" && ctx.User() != username {
				return false
			}
			return password != "" && supplied == password
		},
		PublicKeyHandler: func(ctx gliderssh.Context, key gliderssh.PublicKey) bool {
			if username != "" && ctx.User() != username {
				return false
			}
			return authorizedKey != nil && gliderssh.KeysEqual(key, authorizedKey)
		},
		PtyCallback: func(_ gliderssh.Context, _ gliderssh.Pty) bool {
			return allowPty
		},
		IdleTimeout: 5 * time.Minute,
	}
	for _, signer := range signers {
		server.AddHostKey(signer)
	}

	metadata := ServiceMetadata{
		Service: "ssh",
		Port:    port,
		Config:  config,
		Summary: []ServiceSummaryItem{{Label: "Auth", Value: sshAuthLabel(config)}},
	}
	if metadata.Config["password"] != "" {
		metadata.Config["password"] = "configured"
	}
	if username := config["username"]; username != "" {
		metadata.Summary = append(metadata.Summary, ServiceSummaryItem{Label: "User", Value: username})
	}
	if config["allowPty"] != "false" {
		metadata.Summary = append(metadata.Summary, ServiceSummaryItem{Label: "PTY", Value: "On"})
	}

	return &sshService{metadata: metadata, server: server}, nil
}

func (service *sshService) Metadata() ServiceMetadata {
	return service.metadata
}

func (service *sshService) Start(listener net.Listener) error {
	service.listener = listener
	service.metadata.Active = true
	service.metadata.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	go service.run()
	return nil
}

func (service *sshService) run() {
	if err := service.server.Serve(service.listener); err != nil && !errors.Is(err, net.ErrClosed) {
		service.metadata.LastError = err.Error()
	}
	service.metadata.Active = false
}

func (service *sshService) Close() error {
	closeErr := errors.Join(service.server.Close(), service.listener.Close())
	if service.metadata.LastError != "" {
		return errors.Join(closeErr, errors.New(service.metadata.LastError))
	}
	return closeErr
}

func sshAuthLabel(config map[string]string) string {
	hasPassword := strings.TrimSpace(config["password"]) != ""
	hasKey := strings.TrimSpace(config["authorizedKey"]) != ""

	switch {
	case hasPassword && hasKey:
		return "Pass+Key"
	case hasPassword:
		return "Pass"
	case hasKey:
		return "Key"
	default:
		return "None"
	}
}

func handleKrakenSSHSession(session gliderssh.Session) {
	ptyInfo, winCh, hasPty := session.Pty()
	command, err := resolveSSHCommand(session.Command(), hasPty)
	if err != nil {
		_, _ = io.WriteString(session, err.Error()+"\r\n")
		_ = session.Exit(1)
		return
	}

	if hasPty {
		_ = session.Exit(runSSHPtyCommand(session, command, ptyInfo, winCh))
		return
	}

	_ = session.Exit(runSSHCommand(session, command))
}

func resolveSSHCommand(command []string, hasPty bool) ([]string, error) {
	if len(command) != 0 {
		return command, nil
	}
	if !hasPty {
		return nil, fmt.Errorf("SSH requires a command or terminal. Connect with ssh -t for an interactive shell")
	}
	if runtime.GOOS == "windows" {
		if shell := strings.TrimSpace(os.Getenv("COMSPEC")); shell != "" {
			return []string{shell}, nil
		}
		return []string{"cmd.exe"}, nil
	}

	if shell := strings.TrimSpace(os.Getenv("SHELL")); shell != "" {
		return []string{shell}, nil
	}
	return []string{"/bin/sh"}, nil
}

func runSSHCommand(session gliderssh.Session, command []string) int {
	cmd := exec.CommandContext(session.Context(), command[0], command[1:]...)
	cmd.Env = sshCommandEnv(session, nil)
	cmd.Stdin = session
	cmd.Stdout = session
	cmd.Stderr = session.Stderr()

	return sshCommandExitCode(cmd.Run())
}

func runSSHPtyCommand(session gliderssh.Session, command []string, ptyInfo gliderssh.Pty, winCh <-chan gliderssh.Window) int {
	cmd := exec.CommandContext(session.Context(), command[0], command[1:]...)
	cmd.Env = sshCommandEnv(session, &ptyInfo)

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Rows: uint16(ptyInfo.Window.Height),
		Cols: uint16(ptyInfo.Window.Width),
	})
	if err != nil {
		_, _ = io.WriteString(session, err.Error()+"\r\n")
		return 1
	}
	defer ptmx.Close()

	go func() {
		for win := range winCh {
			_ = pty.Setsize(ptmx, &pty.Winsize{
				Rows: uint16(win.Height),
				Cols: uint16(win.Width),
			})
		}
	}()

	go func() {
		_, _ = io.Copy(ptmx, session)
	}()

	_, _ = io.Copy(session, ptmx)
	return sshCommandExitCode(cmd.Wait())
}

func sshCommandEnv(session gliderssh.Session, ptyInfo *gliderssh.Pty) []string {
	env := append([]string(nil), os.Environ()...)
	env = append(env, session.Environ()...)
	if ptyInfo != nil {
		if term := strings.TrimSpace(ptyInfo.Term); term != "" {
			env = append(env, "TERM="+term)
		}
	}
	return env
}

func sshCommandExitCode(err error) int {
	if err == nil {
		return 0
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

func krakenSSHHostSigners() ([]gossh.Signer, error) {
	hostKeyDir, err := storage.DefaultKrakenConfigDir(filepath.Join("services", "ssh", "hostkeys"))
	if err != nil {
		return nil, err
	}

	return loadOrCreateSSHHostSigners(hostKeyDir)
}

func loadOrCreateSSHHostSigners(hostKeyDir string) ([]gossh.Signer, error) {
	if hostKeyDir == "" {
		return nil, fmt.Errorf("SSH host key directory is unavailable")
	}
	if err := os.MkdirAll(hostKeyDir, 0o755); err != nil {
		return nil, fmt.Errorf("create SSH host key directory: %w", err)
	}

	entries, err := os.ReadDir(hostKeyDir)
	if err != nil {
		return nil, fmt.Errorf("list SSH host keys: %w", err)
	}

	signers := make([]gossh.Signer, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if ext := filepath.Ext(name); ext != "" && ext != ".pem" {
			continue
		}

		signer, err := loadSSHHostSigner(filepath.Join(hostKeyDir, name))
		if err != nil {
			return nil, err
		}
		signers = append(signers, signer)
	}

	if len(signers) != 0 {
		return signers, nil
	}

	defaultKeyPath := filepath.Join(hostKeyDir, "host_ed25519.pem")
	signer, err := createSSHHostSigner(defaultKeyPath)
	if err != nil {
		return nil, err
	}

	return []gossh.Signer{signer}, nil
}

func loadSSHHostSigner(path string) (gossh.Signer, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SSH host key %q: %w", filepath.Base(path), err)
	}

	signer, err := gossh.ParsePrivateKey(payload)
	if err != nil {
		return nil, fmt.Errorf("parse SSH host key %q: %w", filepath.Base(path), err)
	}

	return signer, nil
}

func createSSHHostSigner(path string) (gossh.Signer, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate SSH host key: %w", err)
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("encode SSH host key: %w", err)
	}

	payload := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return nil, fmt.Errorf("write SSH host key %q: %w", filepath.Base(path), err)
	}

	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("load SSH host key %q: %w", filepath.Base(path), err)
	}

	return signer, nil
}

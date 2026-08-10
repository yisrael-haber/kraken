package operations

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/creack/pty"
	gliderssh "github.com/gliderlabs/ssh"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
	gossh "golang.org/x/crypto/ssh"
)

func newSSHService(config map[string]string) (Service, error) {
	port, err := servicePort(config)
	if err != nil {
		return nil, err
	}
	password := config["password"]
	authorizedKeyText := config["authorizedKey"]
	if password == "" && authorizedKeyText == "" {
		return nil, fmt.Errorf("SSH requires a password or authorized key")
	}
	authLabel := "Pass"
	if password == "" {
		authLabel = "Key"
	} else if authorizedKeyText != "" {
		authLabel = "Pass+Key"
	}
	hostKeyDir, err := storage.CreateKrakenConfigDir(filepath.Join("services", "ssh", "hostkeys"))
	if err != nil {
		return nil, err
	}
	hostSigner, err := loadOrCreateSSHHostSigner(filepath.Join(hostKeyDir, "host_ed25519.pem"))
	if err != nil {
		return nil, err
	}

	var authorizedKey gliderssh.PublicKey
	if authorizedKeyText != "" {
		authorizedKey, _, _, _, err = gliderssh.ParseAuthorizedKey([]byte(authorizedKeyText))
		if err != nil {
			return nil, fmt.Errorf("Key: %w", err)
		}
	}

	username := config["username"]
	allowPty := config["allowPty"] != "false"
	server := &gliderssh.Server{
		Handler:         handleKrakenSSHSession,
		HostSigners:     []gliderssh.Signer{hostSigner},
		ChannelHandlers: map[string]gliderssh.ChannelHandler{"session": gliderssh.DefaultSessionHandler},
		PasswordHandler: func(ctx gliderssh.Context, supplied string) bool {
			return (username == "" || ctx.User() == username) && password != "" && supplied == password
		},
		PublicKeyHandler: func(ctx gliderssh.Context, key gliderssh.PublicKey) bool {
			return (username == "" || ctx.User() == username) && authorizedKey != nil && gliderssh.KeysEqual(key, authorizedKey)
		},
		PtyCallback: func(_ gliderssh.Context, _ gliderssh.Pty) bool {
			return allowPty
		},
		IdleTimeout: 5 * time.Minute,
	}

	metadata := ServiceMetadata{
		Service: "ssh",
		Port:    port,
		Config:  config,
		Summary: []ServiceSummaryItem{{Label: "Auth", Value: authLabel}},
	}
	if metadata.Config["password"] != "" {
		metadata.Config["password"] = "configured"
	}
	if username != "" {
		metadata.Summary = append(metadata.Summary, ServiceSummaryItem{Label: "User", Value: username})
	}
	if allowPty {
		metadata.Summary = append(metadata.Summary, ServiceSummaryItem{Label: "PTY", Value: "On"})
	}

	return newTCPService(metadata, func(conn net.Conn) error {
		server.HandleConn(conn)
		return nil
	}), nil
}

func handleKrakenSSHSession(session gliderssh.Session) {
	ptyInfo, winCh, hasPty := session.Pty()
	command, err := resolveSSHCommand(session.Command(), hasPty)
	if err != nil {
		_, _ = io.WriteString(session, err.Error()+"\r\n")
		_ = session.Exit(1)
		return
	}

	var exitCode int
	if hasPty {
		exitCode = runSSHPtyCommand(session, command, ptyInfo, winCh)
	} else {
		exitCode = runSSHCommand(session, command)
	}
	_ = session.Exit(exitCode)
}

func resolveSSHCommand(command []string, hasPty bool) ([]string, error) {
	if len(command) != 0 {
		return command, nil
	}
	if !hasPty {
		return nil, fmt.Errorf("SSH requires a command or terminal. Connect with ssh -t for an interactive shell")
	}
	if runtime.GOOS == "windows" {
		if shell := os.Getenv("COMSPEC"); shell != "" {
			return []string{shell}, nil
		}
		return []string{"cmd.exe"}, nil
	}

	if shell := os.Getenv("SHELL"); shell != "" {
		return []string{shell}, nil
	}
	return []string{"/bin/sh"}, nil
}

func runSSHCommand(session gliderssh.Session, command []string) int {
	cmd := exec.CommandContext(session.Context(), command[0], command[1:]...)
	cmd.Env = sshCommandEnv(session, "")
	cmd.Stdin = session
	cmd.Stdout = session
	cmd.Stderr = session.Stderr()

	return sshCommandExitCode(cmd.Run())
}

func runSSHPtyCommand(session gliderssh.Session, command []string, ptyInfo gliderssh.Pty, winCh <-chan gliderssh.Window) int {
	cmd := exec.CommandContext(session.Context(), command[0], command[1:]...)
	cmd.Env = sshCommandEnv(session, ptyInfo.Term)

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

	go io.Copy(ptmx, session)

	_, _ = io.Copy(session, ptmx)
	return sshCommandExitCode(cmd.Wait())
}

func sshCommandEnv(session gliderssh.Session, term string) []string {
	env := append(os.Environ(), session.Environ()...)
	if term != "" {
		env = append(env, "TERM="+term)
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

func loadOrCreateSSHHostSigner(path string) (gliderssh.Signer, error) {
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return createSSHHostSigner(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read SSH host key %q: %w", filepath.Base(path), err)
	}

	signer, err := gossh.ParsePrivateKey(payload)
	if err != nil {
		return nil, fmt.Errorf("parse SSH host key %q: %w", filepath.Base(path), err)
	}
	return signer, nil
}

func createSSHHostSigner(path string) (gliderssh.Signer, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate SSH host key: %w", err)
	}

	privateKeyPEM, err := gossh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return nil, fmt.Errorf("encode SSH host key: %w", err)
	}

	if err := os.WriteFile(path, pem.EncodeToMemory(privateKeyPEM), 0o600); err != nil {
		return nil, fmt.Errorf("write SSH host key %q: %w", filepath.Base(path), err)
	}

	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("load SSH host key %q: %w", filepath.Base(path), err)
	}

	return signer, nil
}

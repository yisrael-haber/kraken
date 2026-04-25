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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	gliderssh "github.com/gliderlabs/ssh"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
	"github.com/yisrael-haber/kraken/internal/kraken/storeutil"
	gossh "golang.org/x/crypto/ssh"
)

type sshListenerService struct {
	server *gliderssh.Server
	done   chan struct{}

	mu      sync.Mutex
	waitErr error
}

func sshListenerServiceDefinition() ListenerServiceDefinition {
	return ListenerServiceDefinition{
		ID:          listenerServiceSSHID,
		Label:       "SSH",
		DefaultPort: 2222,
		Fields: []adoption.ServiceFieldDefinition{
			{
				Name:         "port",
				Label:        "Port",
				Type:         adoption.ServiceFieldTypePort,
				Required:     true,
				DefaultValue: "2222",
			},
			{
				Name:        "username",
				Label:       "User",
				Type:        adoption.ServiceFieldTypeText,
				Placeholder: "researcher",
			},
			{
				Name:        "password",
				Label:       "Password",
				Type:        adoption.ServiceFieldTypeSecret,
				Placeholder: "secret",
			},
			{
				Name:        "authorizedKey",
				Label:       "Key",
				Type:        adoption.ServiceFieldTypeText,
				Placeholder: "ssh-ed25519 AAAA...",
			},
			{
				Name:         "allowPty",
				Label:        "Terminal",
				Type:         adoption.ServiceFieldTypeSelect,
				DefaultValue: "true",
				Options: []adoption.ServiceFieldOption{
					{Value: "true", Label: "On"},
					{Value: "false", Label: "Off"},
				},
			},
		},
		Start: startSSHListenerService,
		Summary: func(config map[string]string) []adoption.ServiceSummaryItem {
			items := []adoption.ServiceSummaryItem{
				{Label: "Auth", Value: sshAuthLabel(config)},
			}
			if username := strings.TrimSpace(config["username"]); username != "" {
				items = append(items, adoption.ServiceSummaryItem{Label: "User", Value: username})
			}
			if strings.EqualFold(strings.TrimSpace(config["allowPty"]), "true") {
				items = append(items, adoption.ServiceSummaryItem{Label: "PTY", Value: "On"})
			}
			return items
		},
	}
}

func startSSHListenerService(ctx ServiceContext, listener net.Listener, config map[string]string) (RunningService, error) {
	password := config["password"]
	authorizedKeyText := config["authorizedKey"]
	if strings.TrimSpace(password) == "" && strings.TrimSpace(authorizedKeyText) == "" {
		return nil, fmt.Errorf("SSH requires a password or authorized key")
	}
	port, err := strconv.Atoi(config["port"])
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("Port must be between 1 and 65535")
	}

	signers, err := krakenSSHHostSigners()
	if err != nil {
		return nil, err
	}

	var authorizedKey gliderssh.PublicKey
	if strings.TrimSpace(authorizedKeyText) != "" {
		var parseErr error
		authorizedKey, _, _, _, parseErr = gliderssh.ParseAuthorizedKey([]byte(authorizedKeyText))
		if parseErr != nil {
			return nil, fmt.Errorf("Key: %w", parseErr)
		}
	}

	username := strings.TrimSpace(config["username"])
	server := &gliderssh.Server{
		Handler: func(session gliderssh.Session) {
			handleKrakenSSHSession(session)
		},
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
			return strings.EqualFold(strings.TrimSpace(config["allowPty"]), "true")
		},
		IdleTimeout: 5 * time.Minute,
	}
	for _, signer := range signers {
		server.AddHostKey(signer)
	}

	binding, err := newApplicationScriptBinding(ctx, scriptpkg.ApplicationServiceInfo{
		Name:     listenerServiceSSHID,
		Port:     port,
		Protocol: "ssh",
	}, nil)
	if err != nil {
		return nil, err
	}
	listener = wrapListenerWithApplicationScript(listener, binding)

	running := &sshListenerService{
		server: server,
		done:   make(chan struct{}),
	}
	go running.run(listener)
	return running, nil
}

func (service *sshListenerService) run(listener net.Listener) {
	defer close(service.done)

	if err := service.server.Serve(listener); err != nil && !isClosedNetworkError(err) {
		service.setWaitError(fmt.Errorf("serve SSH: %w", err))
	}
}

func (service *sshListenerService) setWaitError(err error) {
	if service == nil || err == nil {
		return
	}

	service.mu.Lock()
	if service.waitErr == nil {
		service.waitErr = err
	}
	service.mu.Unlock()
}

func (service *sshListenerService) Close() error {
	if service == nil {
		return nil
	}

	return service.server.Close()
}

func (service *sshListenerService) Wait() error {
	if service == nil {
		return nil
	}

	<-service.done
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.waitErr
}

func handleKrakenSSHSession(session gliderssh.Session) {
	if session == nil {
		return
	}

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
		return append([]string(nil), command...), nil
	}
	if hasPty {
		return defaultSSHLoginCommand(), nil
	}

	return nil, fmt.Errorf("SSH requires a command or terminal. Connect with ssh -t for an interactive shell")
}

func defaultSSHLoginCommand() []string {
	if runtime.GOOS == "windows" {
		if shell := strings.TrimSpace(os.Getenv("COMSPEC")); shell != "" {
			return []string{shell}
		}
		return []string{"cmd.exe"}
	}

	if shell := strings.TrimSpace(os.Getenv("SHELL")); shell != "" {
		return []string{shell}
	}
	return []string{"/bin/sh"}
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
	if ptyInfo != nil && strings.TrimSpace(ptyInfo.Term) != "" {
		env = append(env, "TERM="+strings.TrimSpace(ptyInfo.Term))
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

func krakenSSHHostSigners() ([]gossh.Signer, error) {
	hostKeyDir, err := storeutil.DefaultKrakenConfigDir(filepath.Join("services", "ssh", "hostkeys"))
	if err != nil {
		return nil, err
	}

	return loadOrCreateSSHHostSigners(hostKeyDir)
}

func loadOrCreateSSHHostSigners(hostKeyDir string) ([]gossh.Signer, error) {
	if strings.TrimSpace(hostKeyDir) == "" {
		return nil, fmt.Errorf("SSH host key directory is unavailable")
	}
	if err := os.MkdirAll(hostKeyDir, 0o755); err != nil {
		return nil, fmt.Errorf("create SSH host key directory: %w", err)
	}

	entries, err := os.ReadDir(hostKeyDir)
	if err != nil {
		return nil, fmt.Errorf("list SSH host keys: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	signers := make([]gossh.Signer, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if ext := strings.ToLower(filepath.Ext(name)); ext != "" && ext != ".pem" {
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

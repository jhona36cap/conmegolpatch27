package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	productID       = "CONMEGOL-PES2021"
	vaultMagic      = "CGSVLT01"
	vaultAAD        = "CONMEGOL-SERVER-VAULT-V1"
	vaultIterations = 500000
	stateVersion    = 2
	apiVersion      = 1
	stateMagic      = "CGSTATE3"
	stateAAD        = "CONMEGOL-STATE-ATREST-V12"
	maxAdmins       = 5
	passwordIters   = 600000
)

var emailRE = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

var machineRE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

var installRE = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)

var errStoreNotFound = errors.New("state not found")

type Vault struct {
	V              int    `json:"v"`
	LicensePrivate string `json:"license_private"`
	StatusPrivate  string `json:"status_private"`
	AdminPIN       string `json:"admin_pin"` // legado; V12 ya no usa PIN
}

type LicensePayload struct {
	Version   int    `json:"v"`
	Product   string `json:"product"`
	Machine   string `json:"machine"`
	EmailHash string `json:"email_hash"`
	RequestID string `json:"request_id"`
	Issued    int64  `json:"issued"`
	Expires   int64  `json:"expires"`
	Serial    string `json:"serial"`
}

type ActivationRequest struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Email           string `json:"email"`
	Machine         string `json:"machine"`
	MachineCode     string `json:"machine_code"`
	InstallID       string `json:"install_id"`
	LauncherVersion string `json:"launcher_version"`
	SecretHash      string `json:"secret_hash"`
	Created         int64  `json:"created"`
	Updated         int64  `json:"updated"`
	LastSeen        int64  `json:"last_seen"`
	Status          string `json:"status"`
	Expires         int64  `json:"expires"`
	Serial          string `json:"serial"`
	License         string `json:"license"`
	DecisionAt      int64  `json:"decision_at"`
	DecisionNote    string `json:"decision_note"`
}

type AdminAccount struct {
	Email    string `json:"email"`
	Salt     string `json:"salt"`
	PassHash string `json:"pass_hash"`
	Created  int64  `json:"created"`
	Updated  int64  `json:"updated"`
}

type PersistentState struct {
	Version  int                  `json:"version"`
	Requests []*ActivationRequest `json:"requests"`
	Admins   []*AdminAccount      `json:"admins"`
}

type legacyStateV1 struct {
	Version  int                  `json:"version"`
	Requests []*ActivationRequest `json:"requests"`
}

type SignedStatusPayload struct {
	Version    int    `json:"v"`
	Product    string `json:"product"`
	ServerTime int64  `json:"server_time"`
	RequestID  string `json:"request_id"`
	Machine    string `json:"machine"`
	Status     string `json:"status"`
	Expires    int64  `json:"expires"`
	License    string `json:"license,omitempty"`
	Message    string `json:"message,omitempty"`
}

type SignedEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type adminSession struct {
	Email   string
	Expires int64
}

type StateStore interface {
	Load(context.Context) ([]byte, error)
	Save(context.Context, []byte) error
	Health(context.Context) error
	Description() string
}

type FileStore struct{ Path string }

func (f *FileStore) Load(ctx context.Context) ([]byte, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errStoreNotFound
	}
	return b, err
}

func (f *FileStore) Save(ctx context.Context, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0700); err != nil {
		return err
	}
	tmp := f.Path + ".tmp"
	if old, err := os.ReadFile(f.Path); err == nil {
		_ = os.WriteFile(f.Path+".bak", old, 0600)
	}
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, f.Path)
}

func (f *FileStore) Health(ctx context.Context) error { return nil }

func (f *FileStore) Description() string { return "archivo local cifrado" }

type RedisStore struct {
	URL       *url.URL
	Key       string
	BackupKey string
}

func NewRedisStore(raw string) (*RedisStore, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "redis" && u.Scheme != "rediss" {
		return nil, fmt.Errorf("REDIS_URL debe usar redis:// o rediss://")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("REDIS_URL sin host")
	}
	return &RedisStore{URL: u, Key: "conmegol:state:v12", BackupKey: "conmegol:state:v12:backup"}, nil
}

func (r *RedisStore) Description() string { return "Render Key Value cifrado" }

func (r *RedisStore) Health(ctx context.Context) error {
	v, err := r.do(ctx, "PING")
	if err != nil {
		return err
	}
	if s, ok := v.(string); ok && strings.EqualFold(s, "PONG") {
		return nil
	}
	return fmt.Errorf("PING inesperado")
}

func (r *RedisStore) Load(ctx context.Context) ([]byte, error) {
	v, err := r.do(ctx, "GET", r.Key)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, errStoreNotFound
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("respuesta GET inválida")
	}
	return b, nil
}

func (r *RedisStore) Save(ctx context.Context, b []byte) error {

	if old, err := r.Load(ctx); err == nil && len(old) > 0 {
		_, _ = r.do(ctx, "SET", r.BackupKey, old)
	}
	v, err := r.do(ctx, "SET", r.Key, b)
	if err != nil {
		return err
	}
	if s, ok := v.(string); !ok || !strings.EqualFold(s, "OK") {
		return fmt.Errorf("SET no confirmado")
	}
	return nil
}

func (r *RedisStore) do(ctx context.Context, args ...any) (any, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("comando vacío")
	}
	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host += ":6379"
	}
	var c net.Conn
	var err error
	d := &net.Dialer{Timeout: 5 * time.Second}
	if r.URL.Scheme == "rediss" {
		servername := r.URL.Hostname()
		c, err = tls.DialWithDialer(d, "tcp", host, &tls.Config{ServerName: servername, MinVersion: tls.VersionTLS12})
	} else {
		c, err = d.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)
	if r.URL.User != nil {
		user := r.URL.User.Username()
		pass, _ := r.URL.User.Password()
		if pass != "" {
			var auth []any
			if user != "" && user != "default" {
				auth = []any{"AUTH", user, pass}
			} else {
				auth = []any{"AUTH", pass}
			}
			if err := writeRESP(bw, auth...); err != nil {
				return nil, err
			}
			if err := bw.Flush(); err != nil {
				return nil, err
			}
			if _, err := readRESP(br); err != nil {
				return nil, fmt.Errorf("AUTH: %w", err)
			}
		}
	}
	if err := writeRESP(bw, args...); err != nil {
		return nil, err
	}
	if err := bw.Flush(); err != nil {
		return nil, err
	}
	return readRESP(br)
}

func writeRESP(w *bufio.Writer, args ...any) error {
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(args)); err != nil {
		return err
	}
	for _, a := range args {
		var b []byte
		switch v := a.(type) {
		case []byte:
			b = v
		case string:
			b = []byte(v)
		default:
			b = []byte(fmt.Sprint(v))
		}
		if _, err := fmt.Fprintf(w, "$%d\r\n", len(b)); err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
		if _, err := w.WriteString("\r\n"); err != nil {
			return err
		}
	}
	return nil
}

func readRESP(r *bufio.Reader) (any, error) {
	p, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	line := func() (string, error) {
		s, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSuffix(strings.TrimSuffix(s, "\n"), "\r"), nil
	}
	switch p {
	case '+':
		return line()
	case '-':
		s, e := line()
		if e != nil {
			return nil, e
		}
		return nil, fmt.Errorf("redis: %s", s)
	case ':':
		s, e := line()
		if e != nil {
			return nil, e
		}
		return strconv.ParseInt(s, 10, 64)
	case '$':
		s, e := line()
		if e != nil {
			return nil, e
		}
		n, e := strconv.Atoi(s)
		if e != nil {
			return nil, e
		}
		if n == -1 {
			return nil, nil
		}
		b := make([]byte, n+2)
		if _, e := io.ReadFull(r, b); e != nil {
			return nil, e
		}
		return b[:n], nil
	default:
		return nil, fmt.Errorf("RESP desconocido: %q", p)
	}
}

type Server struct {
	mu              sync.Mutex
	state           PersistentState
	store           StateStore
	licensePriv     ed25519.PrivateKey
	statusPriv      ed25519.PrivateKey
	stateKey        [32]byte
	setupCodeHash   [32]byte
	sessionsMu      sync.Mutex
	sessions        map[string]adminSession
	attemptsMu      sync.Mutex
	loginAttempts   map[string][]int64
	requestAttempts map[string][]int64
}

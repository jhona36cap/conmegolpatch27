package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type requestInput struct {
	Name            string `json:"name"`
	Email           string `json:"email"`
	Machine         string `json:"machine"`
	InstallID       string `json:"install_id"`
	LauncherVersion string `json:"launcher_version"`
}

type requestOutput struct {
	RequestID     string         `json:"request_id"`
	RequestSecret string         `json:"request_secret"`
	Status        SignedEnvelope `json:"status"`
}

type recoverInput struct {
	Name            string `json:"name"`
	Email           string `json:"email"`
	Machine         string `json:"machine"`
	InstallID       string `json:"install_id"`
	LauncherVersion string `json:"launcher_version"`
	License         string `json:"license"`
}

type statusInput struct {
	RequestID     string `json:"request_id"`
	RequestSecret string `json:"request_secret"`
	Machine       string `json:"machine"`
}

type adminLoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type adminBootstrapInput struct {
	SetupCode string `json:"setup_code"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

type adminCreateInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type adminDeleteInput struct {
	Email string `json:"email"`
}

type adminPasswordInput struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type adminLoginOutput struct {
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
	Email   string `json:"email"`
}

type adminDecisionInput struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Days   int    `json:"days"`
	Note   string `json:"note"`
}

type adminRow struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Email           string `json:"email"`
	Machine         string `json:"machine"`
	MachineCode     string `json:"machine_code"`
	InstallID       string `json:"install_id"`
	LauncherVersion string `json:"launcher_version"`
	Created         int64  `json:"created"`
	Updated         int64  `json:"updated"`
	LastSeen        int64  `json:"last_seen"`
	Status          string `json:"status"`
	Expires         int64  `json:"expires"`
	Serial          string `json:"serial"`
	License         string `json:"license,omitempty"`
	DecisionAt      int64  `json:"decision_at"`
	DecisionNote    string `json:"decision_note"`
}

func main() {
	listen := strings.TrimSpace(os.Getenv("CONMEGOL_LISTEN"))
	if listen == "" {
		listen = "0.0.0.0:" + env("PORT", "8787")
	}
	pass := strings.TrimSpace(os.Getenv("CONMEGOL_SERVER_VAULT_PASSWORD"))
	if pass == "" {
		log.Fatal("Falta CONMEGOL_SERVER_VAULT_PASSWORD")
	}
	setupCode := strings.TrimSpace(os.Getenv("CONMEGOL_ADMIN_SETUP_CODE"))
	if len(setupCode) < 12 {
		log.Fatal("Falta CONMEGOL_ADMIN_SETUP_CODE seguro")
	}
	vb64 := strings.TrimSpace(os.Getenv("CONMEGOL_VAULT_B64"))
	if vb64 == "" {
		log.Fatal("Falta CONMEGOL_VAULT_B64")
	}
	vaultBytes, err := base64.StdEncoding.DecodeString(vb64)
	if err != nil {
		log.Fatalf("CONMEGOL_VAULT_B64 inválido: %v", err)
	}
	v, err := unlockVaultBytes(vaultBytes, pass)
	if err != nil {
		log.Fatalf("Bóveda: %v", err)
	}
	licPriv, err := parseEdPrivate(v.LicensePrivate)
	if err != nil {
		log.Fatal("license key inválida")
	}
	statPriv, err := parseEdPrivate(v.StatusPrivate)
	if err != nil {
		log.Fatal("status key inválida")
	}
	var store StateStore
	if raw := strings.TrimSpace(os.Getenv("REDIS_URL")); raw != "" {
		rs, err := NewRedisStore(raw)
		if err != nil {
			log.Fatalf("REDIS_URL: %v", err)
		}
		store = rs
	} else {
		path := env("CONMEGOL_STATE_FILE", filepath.Join(appDir(), "conmegol_state_v12.cgs"))
		store = &FileStore{Path: path}
	}
	stateKey := sha256.Sum256([]byte("CONMEGOL-STATE-KEY-V12\x00" + pass))
	setupHash := sha256.Sum256([]byte(setupCode))
	s := &Server{
		store: store, licensePriv: licPriv, statusPriv: statPriv, stateKey: stateKey, setupCodeHash: setupHash,
		sessions: map[string]adminSession{}, loginAttempts: map[string][]int64{}, requestAttempts: map[string][]int64{},
	}
	if err := s.loadState(); err != nil {
		log.Fatalf("Estado: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/privacy", s.handlePrivacy)
	mux.HandleFunc("/admin", s.handleAdminPage)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/v1/request", s.handleRequest)
	mux.HandleFunc("/v1/recover", s.handleRecover)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/admin/bootstrap/status", s.handleAdminBootstrapStatus)
	mux.HandleFunc("/v1/admin/bootstrap", s.handleAdminBootstrap)
	mux.HandleFunc("/v1/admin/login", s.handleAdminLogin)
	mux.HandleFunc("/v1/admin/requests", s.handleAdminRequests)
	mux.HandleFunc("/v1/admin/decision", s.handleAdminDecision)
	mux.HandleFunc("/v1/admin/admins", s.handleAdmins)
	mux.HandleFunc("/v1/admin/admins/delete", s.handleAdminDelete)
	mux.HandleFunc("/v1/admin/password", s.handleAdminPassword)

	log.Printf("ConmeGOL License Web V12 FINAL escuchando en %s", listen)
	log.Printf("Persistencia: %s", store.Description())
	srv := &http.Server{Addr: listen, Handler: securityHeaders(mux), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func parseEdPrivate(h string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return nil, err
	}
	if len(b) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(b), nil
	}
	if len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), nil
	}
	return nil, fmt.Errorf("longitud inválida")
}

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func appDir() string { e, _ := os.Executable(); return filepath.Dir(e) }

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != "GET" {
		methodNA(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ConmeGOL Patch</title><style>body{font-family:Segoe UI,Arial;background:#121212;color:#fff;display:grid;place-items:center;min-height:100vh;margin:0}.c{max-width:640px;padding:32px;background:#1f1f1f;border-radius:14px}a{color:#38bdf8}</style></head><body><div class="c"><h2>ConmeGOL Patch</h2><p>Sistema de activación.</p><p><a href="/admin">Administrador</a> · <a href="/privacy">Privacidad</a></p></div></body></html>`)
}

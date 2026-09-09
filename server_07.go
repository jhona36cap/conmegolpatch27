package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func verifyPassword(a *AdminAccount, password string) bool {
	salt, err := base64.RawURLEncoding.DecodeString(a.Salt)
	if err != nil {
		return false
	}
	want, err := base64.RawURLEncoding.DecodeString(a.PassHash)
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, passwordIters, len(want))
	return subtle.ConstantTimeCompare(want, got) == 1
}

func (s *Server) adminAuth(r *http.Request) (string, bool) {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	now := time.Now().Unix()
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	se, ok := s.sessions[tok]
	if !ok || se.Expires < now {
		delete(s.sessions, tok)
		return "", false
	}
	s.mu.Lock()
	exists := s.findAdminLocked(se.Email) != nil
	s.mu.Unlock()
	if !exists {
		delete(s.sessions, tok)
		return "", false
	}
	return se.Email, true
}

func (s *Server) invalidateSessions(email string) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	for t, se := range s.sessions {
		if strings.EqualFold(se.Email, email) {
			delete(s.sessions, t)
		}
	}
}

func (s *Server) issueLicenseLocked(req *ActivationRequest, issued, expires int64) (string, string, error) {
	serial := "CG-" + randomB32(8)
	eh := sha256.Sum256([]byte(strings.ToLower(req.Email)))
	p := LicensePayload{Version: 2, Product: productID, Machine: req.Machine, EmailHash: hex.EncodeToString(eh[:]), RequestID: req.ID, Issued: issued, Expires: expires, Serial: serial}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", "", err
	}
	sig := ed25519.Sign(s.licensePriv, raw)
	return "CGK2-" + base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig), serial, nil
}

func (s *Server) makeStatus(req *ActivationRequest) (SignedEnvelope, error) {
	now := time.Now().Unix()
	status := req.Status
	msg := ""
	if status == "approved" && req.Expires > 0 && now > req.Expires {
		status = "expired"
	}
	switch status {
	case "pending":
		msg = "Solicitud pendiente de aprobación"
	case "approved":
		msg = "Licencia aprobada"
	case "expired":
		msg = "Licencia vencida"
	case "rejected":
		msg = "Solicitud rechazada"
	case "revoked":
		msg = "Licencia revocada"
	}
	p := SignedStatusPayload{Version: 1, Product: productID, ServerTime: now, RequestID: req.ID, Machine: req.Machine, Status: status, Expires: req.Expires, License: req.License, Message: msg}
	raw, err := json.Marshal(p)
	if err != nil {
		return SignedEnvelope{}, err
	}
	sig := ed25519.Sign(s.statusPriv, raw)
	return SignedEnvelope{Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(sig)}, nil
}

func (s *Server) findLatestMachineEmailLocked(machine, email string) *ActivationRequest {
	for i := len(s.state.Requests) - 1; i >= 0; i-- {
		q := s.state.Requests[i]
		if strings.EqualFold(q.Machine, machine) && strings.EqualFold(q.Email, email) {
			return q
		}
	}
	return nil
}

func (s *Server) findLocked(id string) *ActivationRequest {
	for _, q := range s.state.Requests {
		if q.ID == id {
			return q
		}
	}
	return nil
}

func toAdminRow(q *ActivationRequest) adminRow {
	return adminRow{ID: q.ID, Name: q.Name, Email: q.Email, Machine: q.Machine, MachineCode: q.MachineCode, InstallID: q.InstallID, LauncherVersion: q.LauncherVersion, Created: q.Created, Updated: q.Updated, LastSeen: q.LastSeen, Status: q.Status, Expires: q.Expires, Serial: q.Serial, License: q.License, DecisionAt: q.DecisionAt, DecisionNote: q.DecisionNote}
}

func (s *Server) loadState() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := s.store.Load(ctx)
	if errors.Is(err, errStoreNotFound) {
		s.state = PersistentState{Version: stateVersion, Requests: []*ActivationRequest{}, Admins: []*AdminAccount{}}
		return s.saveState()
	}
	if err != nil {
		return err
	}
	var plain []byte
	if len(b) >= 8 && string(b[:8]) == stateMagic {
		if len(b) < 8+12+16 {
			return fmt.Errorf("estado cifrado dañado")
		}
		nonce := b[8:20]
		ct := b[20:]
		block, err := aes.NewCipher(s.stateKey[:])
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		plain, err = gcm.Open(nil, nonce, ct, []byte(stateAAD))
		if err != nil {
			return fmt.Errorf("no se pudo descifrar estado")
		}
	} else {
		plain = b
	}
	var probe struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(plain, &probe); err != nil {
		return err
	}
	switch probe.Version {
	case stateVersion:
		if err := json.Unmarshal(plain, &s.state); err != nil {
			return err
		}
	case 1:
		var old legacyStateV1
		if err := json.Unmarshal(plain, &old); err != nil {
			return err
		}
		s.state = PersistentState{Version: stateVersion, Requests: old.Requests, Admins: []*AdminAccount{}}
		return s.saveState()
	default:
		return fmt.Errorf("versión de estado incompatible")
	}
	if s.state.Requests == nil {
		s.state.Requests = []*ActivationRequest{}
	}
	if s.state.Admins == nil {
		s.state.Admins = []*AdminAccount{}
	}
	if !(len(b) >= 8 && string(b[:8]) == stateMagic) {
		return s.saveState()
	}
	return nil
}

func (s *Server) saveState() error { s.mu.Lock(); defer s.mu.Unlock(); return s.saveStateLocked() }

func (s *Server) saveStateLocked() error {
	plain, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(s.stateKey[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := gcm.Seal(nil, nonce, plain, []byte(stateAAD))
	out := append([]byte(stateMagic), nonce...)
	out = append(out, ct...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.store.Save(ctx, out)
}

func (s *Server) allow(m map[string][]int64, key string, max int, window time.Duration) bool {
	s.attemptsMu.Lock()
	defer s.attemptsMu.Unlock()
	now := time.Now().Unix()
	cut := now - int64(window.Seconds())
	a := m[key]
	b := a[:0]
	for _, t := range a {
		if t >= cut {
			b = append(b, t)
		}
	}
	if len(b) >= max {
		m[key] = b
		return false
	}
	m[key] = append(b, now)
	return true
}

func unlockVaultBytes(b []byte, password string) (*Vault, error) {
	if len(b) < 8+16+12+16 || string(b[:8]) != vaultMagic {
		return nil, fmt.Errorf("formato de bóveda inválido")
	}
	salt := b[8:24]
	nonce := b[24:36]
	ct := b[36:]
	key := pbkdf2SHA256([]byte(password), salt, vaultIterations, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, []byte(vaultAAD))
	if err != nil {
		return nil, fmt.Errorf("contraseña de bóveda incorrecta")
	}
	var v Vault
	if err := json.Unmarshal(plain, &v); err != nil {
		return nil, err
	}
	if v.V != 1 {
		return nil, fmt.Errorf("versión de bóveda incompatible")
	}
	return &v, nil
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	hLen := 32
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	for i := 1; i <= blocks; i++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for j := 1; j < iter; j++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func secureSecret(storedHex, secret string) bool {
	want, err := hex.DecodeString(storedHex)
	if err != nil {
		return false
	}
	got := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(want, got[:]) == 1
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomB32(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func machineCode(machine string) string {
	b, err := hex.DecodeString(machine)
	if err != nil {
		return "CGPC-INVALID"
	}
	return "CGPC-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

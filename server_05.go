package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		methodNA(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.store.Health(ctx); err != nil {
		writeErr(w, 503, "Servicio no disponible")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "product": productID, "server_time": time.Now().Unix(), "api": apiVersion})
}

func normalizeRequest(in *requestInput) error {
	in.Name = strings.TrimSpace(in.Name)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	in.Machine = strings.ToLower(strings.TrimSpace(in.Machine))
	in.InstallID = strings.ToLower(strings.TrimSpace(in.InstallID))
	in.LauncherVersion = strings.TrimSpace(in.LauncherVersion)
	if len([]rune(in.Name)) < 2 || len([]rune(in.Name)) > 80 {
		return fmt.Errorf("Nombre inválido")
	}
	if len(in.Email) > 160 || !emailRE.MatchString(in.Email) {
		return fmt.Errorf("Correo inválido")
	}
	if !machineRE.MatchString(in.Machine) || !installRE.MatchString(in.InstallID) {
		return fmt.Errorf("Identidad de equipo inválida")
	}
	if len(in.LauncherVersion) > 40 {
		return fmt.Errorf("Versión inválida")
	}
	return nil
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNA(w)
		return
	}
	if !s.allow(s.requestAttempts, clientIP(r), 20, time.Hour) {
		writeErr(w, 429, "Demasiadas solicitudes")
		return
	}
	var in requestInput
	if err := decodeJSON(r, &in, 8<<10); err != nil {
		writeErr(w, 400, "Solicitud inválida")
		return
	}
	if err := normalizeRequest(&in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	now := time.Now().Unix()
	secret := randomToken(32)
	sh := sha256.Sum256([]byte(secret))
	s.mu.Lock()
	if existing := s.findLatestMachineEmailLocked(in.Machine, in.Email); existing != nil {
		existing.SecretHash = hex.EncodeToString(sh[:])
		existing.Name = in.Name
		existing.Email = in.Email
		existing.InstallID = in.InstallID
		existing.LauncherVersion = in.LauncherVersion
		existing.LastSeen = now
		existing.Updated = now
		cp := *existing
		err := s.saveStateLocked()
		s.mu.Unlock()
		if err != nil {
			writeErr(w, 500, "No se pudo actualizar la activación")
			return
		}
		env, err := s.makeStatus(&cp)
		if err != nil {
			writeErr(w, 500, "Error de firma")
			return
		}
		writeJSON(w, 200, requestOutput{RequestID: cp.ID, RequestSecret: secret, Status: env})
		return
	}
	req := &ActivationRequest{ID: "CGREQ-" + randomB32(10), Name: in.Name, Email: in.Email, Machine: in.Machine, MachineCode: machineCode(in.Machine), InstallID: in.InstallID, LauncherVersion: in.LauncherVersion, SecretHash: hex.EncodeToString(sh[:]), Created: now, Updated: now, LastSeen: now, Status: "pending"}
	s.state.Requests = append(s.state.Requests, req)
	err := s.saveStateLocked()
	s.mu.Unlock()
	if err != nil {
		writeErr(w, 500, "No se pudo guardar la solicitud")
		return
	}
	env, err := s.makeStatus(req)
	if err != nil {
		writeErr(w, 500, "Error de firma")
		return
	}
	writeJSON(w, 201, requestOutput{RequestID: req.ID, RequestSecret: secret, Status: env})
}

func (s *Server) handleRecover(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNA(w)
		return
	}
	if !s.allow(s.requestAttempts, "recover:"+clientIP(r), 20, time.Hour) {
		writeErr(w, 429, "Demasiadas solicitudes")
		return
	}
	var in recoverInput
	if err := decodeJSON(r, &in, 16<<10); err != nil {
		writeErr(w, 400, "Recuperación inválida")
		return
	}
	base := requestInput{Name: in.Name, Email: in.Email, Machine: in.Machine, InstallID: in.InstallID, LauncherVersion: in.LauncherVersion}
	if err := normalizeRequest(&base); err != nil {
		writeErr(w, 400, "Datos de recuperación inválidos")
		return
	}
	in.Name, in.Email, in.Machine, in.InstallID, in.LauncherVersion = base.Name, base.Email, base.Machine, base.InstallID, base.LauncherVersion
	in.License = strings.TrimSpace(in.License)
	lp, err := s.verifyLicense(in.License)
	if err != nil {
		writeErr(w, 403, "Licencia anterior inválida")
		return
	}
	now := time.Now().Unix()
	eh := sha256.Sum256([]byte(in.Email))
	if lp.Product != productID || !strings.EqualFold(lp.Machine, in.Machine) || !strings.EqualFold(lp.EmailHash, hex.EncodeToString(eh[:])) || (lp.Expires > 0 && now > lp.Expires) {
		writeErr(w, 403, "Licencia anterior no corresponde a esta PC/correo")
		return
	}
	secret := randomToken(32)
	sh := sha256.Sum256([]byte(secret))
	s.mu.Lock()
	if ex := s.findLatestMachineEmailLocked(in.Machine, in.Email); ex != nil {
		ex.SecretHash = hex.EncodeToString(sh[:])
		ex.Name = in.Name
		ex.InstallID = in.InstallID
		ex.LauncherVersion = in.LauncherVersion
		ex.LastSeen = now
		ex.Updated = now
		cp := *ex
		err := s.saveStateLocked()
		s.mu.Unlock()
		if err != nil {
			writeErr(w, 500, "No se pudo recuperar")
			return
		}
		env, _ := s.makeStatus(&cp)
		writeJSON(w, 200, requestOutput{RequestID: cp.ID, RequestSecret: secret, Status: env})
		return
	}
	req := &ActivationRequest{ID: lp.RequestID, Name: in.Name, Email: in.Email, Machine: in.Machine, MachineCode: machineCode(in.Machine), InstallID: in.InstallID, LauncherVersion: in.LauncherVersion, SecretHash: hex.EncodeToString(sh[:]), Created: lp.Issued, Updated: now, LastSeen: now, Status: "approved", Expires: lp.Expires, Serial: lp.Serial, License: in.License, DecisionAt: lp.Issued, DecisionNote: "Migración automática a V12"}
	s.state.Requests = append(s.state.Requests, req)
	err = s.saveStateLocked()
	s.mu.Unlock()
	if err != nil {
		writeErr(w, 500, "No se pudo importar la activación")
		return
	}
	env, _ := s.makeStatus(req)
	writeJSON(w, 200, requestOutput{RequestID: req.ID, RequestSecret: secret, Status: env})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNA(w)
		return
	}
	var in statusInput
	if err := decodeJSON(r, &in, 8<<10); err != nil {
		writeErr(w, 400, "Solicitud inválida")
		return
	}
	in.RequestID = strings.TrimSpace(in.RequestID)
	in.RequestSecret = strings.TrimSpace(in.RequestSecret)
	in.Machine = strings.ToLower(strings.TrimSpace(in.Machine))
	s.mu.Lock()
	req := s.findLocked(in.RequestID)
	if req == nil || !secureSecret(req.SecretHash, in.RequestSecret) || !strings.EqualFold(req.Machine, in.Machine) {
		s.mu.Unlock()
		writeErr(w, 403, "Solicitud no autorizada")
		return
	}
	req.LastSeen = time.Now().Unix()
	req.Updated = req.LastSeen
	_ = s.saveStateLocked()
	cp := *req
	s.mu.Unlock()
	env, err := s.makeStatus(&cp)
	if err != nil {
		writeErr(w, 500, "Error de firma")
		return
	}
	writeJSON(w, 200, env)
}

func (s *Server) verifyLicense(key string) (*LicensePayload, error) {
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, "CGK2-") {
		return nil, fmt.Errorf("formato")
	}
	parts := strings.Split(strings.TrimPrefix(key, "CGK2-"), ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("formato")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	pub := s.licensePriv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, raw, sig) {
		return nil, fmt.Errorf("firma")
	}
	var p LicensePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.Version != 2 {
		return nil, fmt.Errorf("versión")
	}
	return &p, nil
}

func (s *Server) handleAdminBootstrapStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		methodNA(w)
		return
	}
	s.mu.Lock()
	n := len(s.state.Admins)
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"setup_needed": n == 0, "admin_count": n, "max_admins": maxAdmins})
}

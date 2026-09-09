package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (s *Server) handleAdminBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNA(w)
		return
	}
	var in adminBootstrapInput
	if err := decodeJSON(r, &in, 8<<10); err != nil {
		writeErr(w, 400, "Datos inválidos")
		return
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(in.SetupCode)))
	if subtle.ConstantTimeCompare(got[:], s.setupCodeHash[:]) != 1 {
		writeErr(w, 403, "Código de instalación incorrecto")
		return
	}
	s.mu.Lock()
	if len(s.state.Admins) != 0 {
		s.mu.Unlock()
		writeErr(w, 409, "La configuración inicial ya fue realizada")
		return
	}
	if err := s.createAdminLocked(in.Email, in.Password); err != nil {
		s.mu.Unlock()
		writeErr(w, 400, err.Error())
		return
	}
	err := s.saveStateLocked()
	s.mu.Unlock()
	if err != nil {
		writeErr(w, 500, "No se pudo guardar")
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true})
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNA(w)
		return
	}
	if !s.allow(s.loginAttempts, clientIP(r), 8, 15*time.Minute) {
		writeErr(w, 429, "Demasiados intentos")
		return
	}
	var in adminLoginInput
	if err := decodeJSON(r, &in, 8<<10); err != nil {
		writeErr(w, 400, "Ingreso inválido")
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	s.mu.Lock()
	a := s.findAdminLocked(email)
	ok := a != nil && verifyPassword(a, in.Password)
	s.mu.Unlock()
	if !ok {
		writeErr(w, 403, "Correo o contraseña incorrectos")
		return
	}
	token := randomToken(32)
	exp := time.Now().Add(8 * time.Hour).Unix()
	s.sessionsMu.Lock()
	s.sessions[token] = adminSession{Email: email, Expires: exp}
	s.sessionsMu.Unlock()
	writeJSON(w, 200, adminLoginOutput{Token: token, Expires: exp, Email: email})
}

func (s *Server) handleAdminRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		methodNA(w)
		return
	}
	if _, ok := s.adminAuth(r); !ok {
		writeErr(w, 401, "Sesión ADMIN inválida")
		return
	}
	s.mu.Lock()
	rows := make([]adminRow, 0, len(s.state.Requests))
	for i := len(s.state.Requests) - 1; i >= 0; i-- {
		rows = append(rows, toAdminRow(s.state.Requests[i]))
	}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"server_time": time.Now().Unix(), "requests": rows})
}

func (s *Server) handleAdminDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNA(w)
		return
	}
	if _, ok := s.adminAuth(r); !ok {
		writeErr(w, 401, "Sesión ADMIN inválida")
		return
	}
	var in adminDecisionInput
	if err := decodeJSON(r, &in, 8<<10); err != nil {
		writeErr(w, 400, "Decisión inválida")
		return
	}
	in.ID = strings.TrimSpace(in.ID)
	in.Action = strings.ToLower(strings.TrimSpace(in.Action))
	in.Note = strings.TrimSpace(in.Note)
	if len(in.Note) > 200 {
		in.Note = in.Note[:200]
	}
	if in.Days < 0 || in.Days > 3650 {
		writeErr(w, 400, "Duración inválida")
		return
	}
	now := time.Now().Unix()
	s.mu.Lock()
	req := s.findLocked(in.ID)
	if req == nil {
		s.mu.Unlock()
		writeErr(w, 404, "Solicitud inexistente")
		return
	}
	switch in.Action {
	case "approve":
		exp := int64(0)
		if in.Days > 0 {
			exp = time.Now().Add(time.Duration(in.Days) * 24 * time.Hour).Unix()
		}
		lic, serial, err := s.issueLicenseLocked(req, now, exp)
		if err != nil {
			s.mu.Unlock()
			writeErr(w, 500, "No se pudo firmar la licencia")
			return
		}
		req.Status = "approved"
		req.Expires = exp
		req.Serial = serial
		req.License = lic
		req.DecisionAt = now
		req.DecisionNote = in.Note
	case "reject":
		req.Status = "rejected"
		req.License = ""
		req.Serial = ""
		req.Expires = 0
		req.DecisionAt = now
		req.DecisionNote = in.Note
	case "revoke":
		req.Status = "revoked"
		req.DecisionAt = now
		req.DecisionNote = in.Note
	default:
		s.mu.Unlock()
		writeErr(w, 400, "Acción inválida")
		return
	}
	req.Updated = now
	err := s.saveStateLocked()
	cp := *req
	s.mu.Unlock()
	if err != nil {
		writeErr(w, 500, "No se pudo guardar")
		return
	}
	writeJSON(w, 200, toAdminRow(&cp))
}

func (s *Server) handleAdmins(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminAuth(r); !ok {
		writeErr(w, 401, "Sesión ADMIN inválida")
		return
	}
	switch r.Method {
	case "GET":
		s.mu.Lock()
		out := make([]map[string]any, 0, len(s.state.Admins))
		for _, a := range s.state.Admins {
			out = append(out, map[string]any{"email": a.Email, "created": a.Created})
		}
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"admins": out, "max_admins": maxAdmins})
	case "POST":
		var in adminCreateInput
		if err := decodeJSON(r, &in, 8<<10); err != nil {
			writeErr(w, 400, "Datos inválidos")
			return
		}
		s.mu.Lock()
		if err := s.createAdminLocked(in.Email, in.Password); err != nil {
			s.mu.Unlock()
			writeErr(w, 400, err.Error())
			return
		}
		err := s.saveStateLocked()
		s.mu.Unlock()
		if err != nil {
			writeErr(w, 500, "No se pudo guardar")
			return
		}
		writeJSON(w, 201, map[string]any{"ok": true})
	default:
		methodNA(w)
	}
}

func (s *Server) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNA(w)
		return
	}
	if _, ok := s.adminAuth(r); !ok {
		writeErr(w, 401, "Sesión ADMIN inválida")
		return
	}
	var in adminDeleteInput
	if err := decodeJSON(r, &in, 4<<10); err != nil {
		writeErr(w, 400, "Datos inválidos")
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	s.mu.Lock()
	if len(s.state.Admins) <= 1 {
		s.mu.Unlock()
		writeErr(w, 409, "No se puede eliminar el último administrador")
		return
	}
	idx := -1
	for i, a := range s.state.Admins {
		if strings.EqualFold(a.Email, email) {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.mu.Unlock()
		writeErr(w, 404, "Administrador inexistente")
		return
	}
	s.state.Admins = append(s.state.Admins[:idx], s.state.Admins[idx+1:]...)
	err := s.saveStateLocked()
	s.mu.Unlock()
	if err != nil {
		writeErr(w, 500, "No se pudo guardar")
		return
	}
	s.invalidateSessions(email)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleAdminPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNA(w)
		return
	}
	email, ok := s.adminAuth(r)
	if !ok {
		writeErr(w, 401, "Sesión ADMIN inválida")
		return
	}
	var in adminPasswordInput
	if err := decodeJSON(r, &in, 8<<10); err != nil {
		writeErr(w, 400, "Datos inválidos")
		return
	}
	if err := validatePassword(in.NewPassword); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.mu.Lock()
	a := s.findAdminLocked(email)
	if a == nil || !verifyPassword(a, in.CurrentPassword) {
		s.mu.Unlock()
		writeErr(w, 403, "Contraseña actual incorrecta")
		return
	}
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	a.Salt = base64.RawURLEncoding.EncodeToString(salt)
	a.PassHash = base64.RawURLEncoding.EncodeToString(pbkdf2SHA256([]byte(in.NewPassword), salt, passwordIters, 32))
	a.Updated = time.Now().Unix()
	err := s.saveStateLocked()
	s.mu.Unlock()
	if err != nil {
		writeErr(w, 500, "No se pudo guardar")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) createAdminLocked(email, password string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if len(s.state.Admins) >= maxAdmins {
		return fmt.Errorf("Máximo de 5 administradores alcanzado")
	}
	if len(email) > 160 || !emailRE.MatchString(email) {
		return fmt.Errorf("Correo inválido")
	}
	if s.findAdminLocked(email) != nil {
		return fmt.Errorf("Ese correo ya es administrador")
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	now := time.Now().Unix()
	a := &AdminAccount{Email: email, Salt: base64.RawURLEncoding.EncodeToString(salt), PassHash: base64.RawURLEncoding.EncodeToString(pbkdf2SHA256([]byte(password), salt, passwordIters, 32)), Created: now, Updated: now}
	s.state.Admins = append(s.state.Admins, a)
	return nil
}

func validatePassword(p string) error {
	if len(p) < 10 {
		return fmt.Errorf("La contraseña debe tener al menos 10 caracteres")
	}
	if len(p) > 200 {
		return fmt.Errorf("Contraseña demasiado larga")
	}
	return nil
}

func (s *Server) findAdminLocked(email string) *AdminAccount {
	for _, a := range s.state.Admins {
		if strings.EqualFold(a.Email, email) {
			return a
		}
	}
	return nil
}

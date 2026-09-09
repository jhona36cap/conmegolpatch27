package main

import (
	"io"
	"net/http"
)

func (s *Server) handlePrivacy(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		methodNA(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Privacidad - ConmeGOL</title><style>body{font-family:Segoe UI,Arial;background:#121212;color:#eee;max-width:760px;margin:50px auto;padding:0 20px}h1{color:#fff}a{color:#38bdf8}</style></head><body><h1>Privacidad</h1><p>El sistema recibe únicamente el nombre y correo que el cliente escribe, un identificador derivado de la PC (HWID), un identificador aleatorio de instalación y la versión del launcher. Se utilizan exclusivamente para gestionar la licencia.</p><p>No lee ni envía archivos personales, historial del navegador, contraseñas, fotos ni documentos.</p><p>Los registros de activación se almacenan cifrados y las contraseñas administrativas se guardan únicamente como hash con salt.</p><p><a href="/">Volver</a></p></body></html>`)
}

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		methodNA(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, adminHTML)
}

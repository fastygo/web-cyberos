package main

import (
	"html/template"
	"net/http"
	"path/filepath"
)

type SiteHandlers struct {
	homeTpl      *template.Template
	dashboardTpl *template.Template
}

func NewSiteHandlers() *SiteHandlers {
	tplDir := "templates"
	return &SiteHandlers{
		homeTpl:      template.Must(template.ParseFiles(filepath.Join(tplDir, "home.html"))),
		dashboardTpl: template.Must(template.ParseFiles(filepath.Join(tplDir, "dashboard.html"))),
	}
}

func (h *SiteHandlers) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	h.homeTpl.Execute(w, nil)
}

func (h *SiteHandlers) handleDashboard(w http.ResponseWriter, r *http.Request) {
	email := getUserEmail(r)
	h.dashboardTpl.Execute(w, map[string]string{
		"Email": email,
	})
}

func (h *SiteHandlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   siteSessionCookie,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

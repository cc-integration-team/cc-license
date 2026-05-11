package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"namitech.io/cc-license/license"
)

//go:embed templates/*.html
var templateFS embed.FS

type Server struct{}

func NewServer() *Server { return &Server{} }

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/genkey", s.handleGenKey)
	mux.HandleFunc("/genkey/download", s.handleGenKeyDownload)
	mux.HandleFunc("/sign", s.handleSign)
	mux.HandleFunc("/sign/download", s.handleSignDownload)
	mux.HandleFunc("/verify", s.handleVerify)
	return mux
}

type pageData struct {
	Title  string
	Active string

	Error string

	KeyPair *license.KeyPair

	Form       signForm
	Result     *license.SignedLicense
	ResultJSON string
	Encoded    string

	Valid     bool
	IssuedAt  string
	ExpiresAt string
}

type signForm struct {
	Priv     string
	Org      string
	ID       string
	Issued   string
	Days     string
	Features string

	Pub     string
	License string
}

func (s *Server) renderLayout(w http.ResponseWriter, contentTpl string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tpl, err := template.ParseFS(templateFS, "templates/layout.html", "templates/"+contentTpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.renderLayout(w, "index.html", pageData{Title: "Home", Active: "home"})
}

func (s *Server) handleGenKey(w http.ResponseWriter, r *http.Request) {
	data := pageData{Title: "Generate Key", Active: "genkey"}
	if r.Method == http.MethodPost {
		kp, err := license.GenerateKeyPair()
		if err != nil {
			data.Error = err.Error()
		} else {
			data.KeyPair = &kp
		}
	}
	s.renderLayout(w, "genkey.html", data)
}

func (s *Server) handleGenKeyDownload(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch q.Get("type") {
	case "public":
		key := q.Get("key")
		if key == "" {
			http.Error(w, "missing key", http.StatusBadRequest)
			return
		}
		writeAttachment(w, "public.key", "text/plain", []byte(key))
	case "private":
		key := q.Get("key")
		if key == "" {
			http.Error(w, "missing key", http.StatusBadRequest)
			return
		}
		writeAttachment(w, "private.key", "text/plain", []byte(key))
	case "pair":
		pub, priv := q.Get("pub"), q.Get("priv")
		if pub == "" || priv == "" {
			http.Error(w, "missing keys", http.StatusBadRequest)
			return
		}
		body, _ := json.MarshalIndent(license.KeyPair{PublicKey: pub, PrivateKey: priv}, "", "  ")
		writeAttachment(w, "keypair.json", "application/json", body)
	default:
		http.Error(w, "unknown type", http.StatusBadRequest)
	}
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	data := pageData{Title: "Sign", Active: "sign"}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			data.Error = err.Error()
			s.renderLayout(w, "sign.html", data)
			return
		}
		f := signForm{
			Priv:     strings.TrimSpace(r.FormValue("priv")),
			Org:      strings.TrimSpace(r.FormValue("org")),
			ID:       strings.TrimSpace(r.FormValue("id")),
			Issued:   strings.TrimSpace(r.FormValue("issued")),
			Days:     strings.TrimSpace(r.FormValue("days")),
			Features: strings.TrimSpace(r.FormValue("features")),
		}
		data.Form = f

		signed, encoded, err := signFromForm(f)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Result = &signed
			data.Encoded = encoded
			pretty, _ := json.MarshalIndent(signed, "", "  ")
			data.ResultJSON = string(pretty)
		}
	}
	s.renderLayout(w, "sign.html", data)
}

func signFromForm(f signForm) (license.SignedLicense, string, error) {
	if f.Org == "" {
		return license.SignedLicense{}, "", fmt.Errorf("organization is required")
	}
	if f.Priv == "" {
		return license.SignedLicense{}, "", fmt.Errorf("private key is required")
	}
	priv, err := license.ParsePrivateKey(f.Priv)
	if err != nil {
		return license.SignedLicense{}, "", err
	}
	issuedAt := time.Now()
	if f.Issued != "" {
		issuedAt, err = parseIssuedAt(f.Issued)
		if err != nil {
			return license.SignedLicense{}, "", fmt.Errorf("issued: %w", err)
		}
	}
	days := 365
	if f.Days != "" {
		days, err = strconv.Atoi(f.Days)
		if err != nil || days < 1 {
			return license.SignedLicense{}, "", fmt.Errorf("days must be a positive integer")
		}
	}
	var feats []string
	if f.Features != "" {
		for _, x := range strings.Split(f.Features, ",") {
			if x = strings.TrimSpace(x); x != "" {
				feats = append(feats, x)
			}
		}
	}
	lic := license.License{
		ID:           f.ID,
		Organization: f.Org,
		IssuedAt:     issuedAt,
		ExpiresAt:    issuedAt.AddDate(0, 0, days),
		Features:     feats,
	}
	signed, err := lic.Sign(priv)
	if err != nil {
		return license.SignedLicense{}, "", err
	}
	encoded, err := signed.Encode()
	if err != nil {
		return license.SignedLicense{}, "", err
	}
	return signed, encoded, nil
}

func (s *Server) handleSignDownload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	encoded := strings.TrimSpace(r.FormValue("encoded"))
	if encoded == "" {
		http.Error(w, "missing encoded license", http.StatusBadRequest)
		return
	}
	if r.FormValue("format") == "json" {
		signed, err := license.Decode(encoded)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body, _ := json.MarshalIndent(signed, "", "  ")
		writeAttachment(w, "license.json", "application/json", body)
		return
	}
	writeAttachment(w, "license.txt", "text/plain", []byte(encoded))
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	data := pageData{Title: "Verify", Active: "verify"}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			data.Error = err.Error()
			s.renderLayout(w, "verify.html", data)
			return
		}
		data.Form = signForm{
			Pub:     strings.TrimSpace(r.FormValue("pub")),
			License: strings.TrimSpace(r.FormValue("license")),
		}
		if data.Form.Pub == "" || data.Form.License == "" {
			data.Error = "public key và license không được để trống"
		} else if err := verifyFromForm(data.Form, &data); err != nil {
			data.Error = err.Error()
		}
	}
	s.renderLayout(w, "verify.html", data)
}

func verifyFromForm(f signForm, data *pageData) error {
	pub, err := license.ParsePublicKey(f.Pub)
	if err != nil {
		return err
	}
	signed, err := license.Decode(f.License)
	if err != nil {
		return err
	}
	if err := signed.Verify(pub); err != nil {
		return err
	}
	pretty, _ := json.MarshalIndent(signed.License, "", "  ")
	data.Valid = true
	data.Result = &signed
	data.ResultJSON = string(pretty)
	data.IssuedAt = signed.License.IssuedAt.Format(time.RFC3339)
	data.ExpiresAt = signed.License.ExpiresAt.Format(time.RFC3339)
	return nil
}

// parseIssuedAt accepts either an HTML datetime-local value
// (YYYY-MM-DDTHH:MM[:SS]) — interpreted in the server's local timezone —
// or a full RFC3339 timestamp.
func parseIssuedAt(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Parse(time.RFC3339, s)
}

func writeAttachment(w http.ResponseWriter, filename, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

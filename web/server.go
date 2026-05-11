package web

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cc-integration-team/cc-license/license"
)

const maxUploadBytes = 1 << 20 // 1 MiB cap for key/license uploads

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
	Expires  string
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
			data.KeyPair = kp
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
	default:
		http.Error(w, "unknown type", http.StatusBadRequest)
	}
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	data := pageData{Title: "Sign", Active: "sign"}
	if r.Method == http.MethodPost {
		if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
			data.Error = err.Error()
			s.renderLayout(w, "sign.html", data)
			return
		}
		priv, err := readUploadOrText(r, "priv", "priv_file")
		if err != nil {
			data.Error = err.Error()
			s.renderLayout(w, "sign.html", data)
			return
		}
		f := signForm{
			Priv:     priv,
			Org:      strings.TrimSpace(r.FormValue("org")),
			ID:       strings.TrimSpace(r.FormValue("id")),
			Expires:  strings.TrimSpace(r.FormValue("expires")),
			Features: strings.TrimSpace(r.FormValue("features")),
		}
		data.Form = f

		signed, encoded, err := signFromForm(f)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Result = signed
			data.Encoded = encoded
			pretty, _ := json.MarshalIndent(signed, "", "  ")
			data.ResultJSON = string(pretty)
		}
	}
	s.renderLayout(w, "sign.html", data)
}

func signFromForm(f signForm) (*license.SignedLicense, string, error) {
	if f.Org == "" {
		return nil, "", fmt.Errorf("organization is required")
	}
	if f.Priv == "" {
		return nil, "", fmt.Errorf("private key is required")
	}
	if f.Expires == "" {
		return nil, "", fmt.Errorf("expiration date is required")
	}
	priv, err := license.ParsePrivateKey(f.Priv)
	if err != nil {
		return nil, "", err
	}
	issuedAt := time.Now().UTC()
	expiresAt, err := parseDateTime(f.Expires)
	if err != nil {
		return nil, "", fmt.Errorf("expires: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return nil, "", fmt.Errorf("expires must be in the future")
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
		ExpiresAt:    expiresAt,
		Features:     feats,
	}
	signed, err := lic.Sign(priv)
	if err != nil {
		return nil, "", err
	}
	encoded, err := signed.Encode()
	if err != nil {
		return nil, "", err
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
	writeAttachment(w, "license.lic", "text/plain", []byte(encoded))
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	data := pageData{Title: "Verify", Active: "verify"}
	if r.Method == http.MethodPost {
		if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
			data.Error = err.Error()
			s.renderLayout(w, "verify.html", data)
			return
		}
		pub, err := readUploadOrText(r, "pub", "pub_file")
		if err != nil {
			data.Error = err.Error()
			s.renderLayout(w, "verify.html", data)
			return
		}
		licData, err := readUploadOrText(r, "license", "license_file")
		if err != nil {
			data.Error = err.Error()
			s.renderLayout(w, "verify.html", data)
			return
		}
		data.Form = signForm{Pub: pub, License: licData}
		if data.Form.Pub == "" || data.Form.License == "" {
			data.Error = "public key and license must not be empty"
		} else if err := verifyFromForm(data.Form, &data); err != nil {
			data.Error = err.Error()
		}
	}
	s.renderLayout(w, "verify.html", data)
}

// readUploadOrText returns the trimmed content of the uploaded file
// at fileField if present, otherwise the trimmed value of textField.
// Upload size is capped by the surrounding ParseMultipartForm limit.
func readUploadOrText(r *http.Request, textField, fileField string) (string, error) {
	f, _, err := r.FormFile(fileField)
	if err == nil {
		defer f.Close()
		b, readErr := io.ReadAll(io.LimitReader(f, maxUploadBytes))
		if readErr != nil {
			return "", fmt.Errorf("read %s: %w", fileField, readErr)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if !errors.Is(err, http.ErrMissingFile) {
		return "", fmt.Errorf("%s upload: %w", fileField, err)
	}
	return strings.TrimSpace(r.FormValue(textField)), nil
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
	if err := license.Verify(signed, pub); err != nil {
		return err
	}
	pretty, _ := json.MarshalIndent(signed.License, "", "  ")
	data.Valid = true
	data.Result = signed
	data.ResultJSON = string(pretty)
	data.IssuedAt = signed.License.IssuedAt.UTC().Format(time.RFC3339)
	data.ExpiresAt = signed.License.ExpiresAt.UTC().Format(time.RFC3339)
	return nil
}

// parseDateTime accepts an HTML datetime-local value
// (YYYY-MM-DDTHH:MM[:SS]) interpreted as UTC, or a full RFC3339 timestamp.
func parseDateTime(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, nil
		}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func writeAttachment(w http.ResponseWriter, filename, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

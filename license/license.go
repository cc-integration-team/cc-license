// Package license issues and verifies ed25519-signed software licenses.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// License holds the data signed with ed25519. Timestamps preserve
// their original timezone via RFC3339 round-trip.
type License struct {
	ID           string    `json:"id,omitempty"`
	Organization string    `json:"organization"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Features     []string  `json:"features,omitempty"`
}

// normalize returns a copy of the License with timestamps truncated to
// second precision so the canonical JSON is stable across signing and
// JSON round-trips during verification.
func (l License) normalize() License {
	l.IssuedAt = l.IssuedAt.Truncate(time.Second)
	l.ExpiresAt = l.ExpiresAt.Truncate(time.Second)
	return l
}

// canonicalBytes returns the deterministic JSON representation used as
// the signing payload. encoding/json marshals struct fields in
// declaration order, so the result is reproducible.
func (l License) canonicalBytes() ([]byte, error) {
	return json.Marshal(l)
}

// Sign signs the License with the given private key and returns a
// SignedLicense containing both the normalized license and the signature.
func (l License) Sign(priv ed25519.PrivateKey) (*SignedLicense, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key")
	}
	if l.ID == "" {
		l.ID = uuid.NewString()
	}
	norm := l.normalize()
	b, err := norm.canonicalBytes()
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, b)
	return &SignedLicense{
		License:   norm,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

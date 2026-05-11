package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
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

// SignedLicense pairs a License with its base64 ed25519 signature.
type SignedLicense struct {
	License   License `json:"license"`
	Signature string  `json:"signature"`
}

// KeyPair stores an ed25519 key pair as base64 strings for easy
// transport (paste into UI, store in env, etc.).
type KeyPair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// GenerateKeyPair returns a fresh ed25519 key pair encoded as base64.
func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	}, nil
}

// ParsePrivateKey decodes a base64-encoded ed25519 private key.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(b))
	}
	return ed25519.PrivateKey(b), nil
}

// ParsePublicKey decodes a base64-encoded ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
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
// SignedLicense containing both the original license and the signature.
func (l License) Sign(priv ed25519.PrivateKey) (SignedLicense, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SignedLicense{}, errors.New("invalid private key")
	}
	norm := l.normalize()
	b, err := norm.canonicalBytes()
	if err != nil {
		return SignedLicense{}, err
	}
	sig := ed25519.Sign(priv, b)
	return SignedLicense{
		License:   norm,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify checks the signature with the given public key and ensures the
// license has not expired.
func (s SignedLicense) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	b, err := s.License.canonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, sig) {
		return errors.New("signature verification failed")
	}
	if time.Now().After(s.License.ExpiresAt) {
		return errors.New("license has expired")
	}
	return nil
}

// Encode packs a SignedLicense into a base64 string suitable for
// distribution.
func (s SignedLicense) Encode() (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// Decode parses a base64-encoded SignedLicense produced by Encode.
func Decode(s string) (SignedLicense, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return SignedLicense{}, fmt.Errorf("decode license: %w", err)
	}
	var sl SignedLicense
	if err := json.Unmarshal(b, &sl); err != nil {
		return SignedLicense{}, fmt.Errorf("unmarshal license: %w", err)
	}
	return sl, nil
}

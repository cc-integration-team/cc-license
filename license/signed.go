package license

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// SignedLicense pairs a License with its base64 ed25519 signature.
type SignedLicense struct {
	License   License `json:"license"`
	Signature string  `json:"signature"`
}

// Encode packs a SignedLicense into a base64 string suitable for
// distribution.
func (s *SignedLicense) Encode() (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// Decode parses a base64-encoded SignedLicense produced by Encode.
func Decode(s string) (*SignedLicense, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("decode license: %w", err)
	}
	var sl SignedLicense
	if err := json.Unmarshal(b, &sl); err != nil {
		return nil, fmt.Errorf("unmarshal license: %w", err)
	}
	return &sl, nil
}

package license

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"
)

// Verify checks the signature on a SignedLicense with the given public
// key and ensures the license has not expired.
func Verify(s *SignedLicense, pub ed25519.PublicKey) error {
	if s == nil {
		return errors.New("nil signed license")
	}
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

// VerifyFromFile reads an encoded license from the given file path and
// verifies it against the base64-encoded public key. Returns the decoded
// SignedLicense on success.
func VerifyFromFile(path string, pubKeyBase64 string) (*SignedLicense, error) {
	pub, err := ParsePublicKey(pubKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read license file: %w", err)
	}
	signed, err := Decode(string(data))
	if err != nil {
		return nil, err
	}
	if err := Verify(signed, pub); err != nil {
		return nil, err
	}
	return signed, nil
}

// VerifyInterval periodically re-reads the license file and verifies it.
// It returns an error channel that receives the first verification failure.
// The caller should select on this channel and terminate when an error
// arrives. The channel is closed when ctx is cancelled.
//
// Usage in main:
//
//	errCh := license.VerifyInterval(ctx, "license.txt", pubKey, 1*time.Hour)
//	if err := <-errCh; err != nil {
//	    log.Fatalf("license check failed: %v", err)
//	}
func VerifyInterval(ctx context.Context, path string, pubKeyBase64 string, interval time.Duration) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := VerifyFromFile(path, pubKeyBase64); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()
	return errCh
}

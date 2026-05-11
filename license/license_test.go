package license

import (
	"strings"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	priv, err := ParsePrivateKey(kp.PrivateKey)
	if err != nil {
		t.Fatalf("parse priv: %v", err)
	}
	pub, err := ParsePublicKey(kp.PublicKey)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}

	now := time.Now()
	lic := License{
		ID:           "LIC-001",
		Organization: "Nami Tech",
		IssuedAt:     now,
		ExpiresAt:    now.Add(30 * 24 * time.Hour),
		Features:     []string{"a", "b"},
	}

	signed, err := lic.Sign(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := signed.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	encoded, err := signed.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := decoded.Verify(pub); err != nil {
		t.Fatalf("verify after roundtrip: %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	kp, _ := GenerateKeyPair()
	priv, _ := ParsePrivateKey(kp.PrivateKey)
	pub, _ := ParsePublicKey(kp.PublicKey)

	now := time.Now()
	lic := License{
		Organization: "Nami Tech",
		IssuedAt:     now.Add(-2 * time.Hour),
		ExpiresAt:    now.Add(-1 * time.Hour),
	}
	signed, _ := lic.Sign(priv)
	err := signed.Verify(pub)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}
}

func TestVerifyTampered(t *testing.T) {
	kp, _ := GenerateKeyPair()
	priv, _ := ParsePrivateKey(kp.PrivateKey)
	pub, _ := ParsePublicKey(kp.PublicKey)

	now := time.Now()
	lic := License{
		Organization: "Nami Tech",
		IssuedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
	}
	signed, _ := lic.Sign(priv)
	signed.License.Organization = "Attacker"
	if err := signed.Verify(pub); err == nil {
		t.Fatal("expected verification failure on tampered license")
	}
}

func TestParseInvalidKey(t *testing.T) {
	if _, err := ParsePrivateKey("not-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if _, err := ParsePublicKey("c2hvcnQ="); err == nil {
		t.Fatal("expected error for short public key")
	}
}

func TestTimezonePreserved(t *testing.T) {
	kp, _ := GenerateKeyPair()
	priv, _ := ParsePrivateKey(kp.PrivateKey)
	pub, _ := ParsePublicKey(kp.PublicKey)

	loc, err := time.LoadLocation("Asia/Ho_Chi_Minh")
	if err != nil {
		t.Skipf("tz not available: %v", err)
	}
	issued := time.Date(2026, 5, 7, 10, 0, 0, 0, loc)
	lic := License{
		Organization: "Nami Tech",
		IssuedAt:     issued,
		ExpiresAt:    issued.AddDate(1, 0, 0),
	}
	signed, _ := lic.Sign(priv)
	encoded, _ := signed.Encode()
	decoded, _ := Decode(encoded)

	if _, off := decoded.License.IssuedAt.Zone(); off != 7*3600 {
		t.Fatalf("expected +07:00 offset, got %d", off)
	}
	if err := decoded.Verify(pub); err != nil {
		t.Fatalf("verify after tz roundtrip: %v", err)
	}
}

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cc-integration-team/cc-license/license"
	"github.com/cc-integration-team/cc-license/web"
)

const usage = `cc-license - sign software licenses with ed25519

Commands:
  genkey                              Generate an ed25519 key pair (base64)
  sign   -priv <key>  -org <name>     Sign a license. Private key may be piped via stdin
         [-id <id>] [-days <n>] [-issued <RFC3339>] [-features a,b]
  verify -pub  <key>  -license <enc>  Verify a signed license. License may be piped via stdin
  serve  [-addr :8080]                Launch the web UI to issue / verify licenses

Examples:
  cc-license genkey
  cc-license sign -priv "$PRIV" -org "Nami Tech" -days 365 -features core,api
  echo "$PRIV" | cc-license sign -org "Nami Tech" -days 30
  cc-license verify -pub "$PUB" -license "$LIC"
  cc-license serve -addr :8080
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "genkey":
		if err := runGenKey(); err != nil {
			fail(err)
		}
	case "sign":
		if err := runSign(os.Args[2:]); err != nil {
			fail(err)
		}
	case "verify":
		if err := runVerify(os.Args[2:]); err != nil {
			fail(err)
		}
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			fail(err)
		}
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func runGenKey() error {
	kp, err := license.GenerateKeyPair()
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(kp, "", "  ")
	fmt.Println(string(out))
	return nil
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	priv := fs.String("priv", "", "private key (base64); empty to read from stdin")
	org := fs.String("org", "", "organization name")
	id := fs.String("id", "", "license id (optional)")
	days := fs.Int("days", 365, "validity in days starting from -issued")
	issued := fs.String("issued", "", "issue date in RFC3339, e.g. 2026-05-07T10:00:00+07:00 (default: now)")
	features := fs.String("features", "", "comma-separated feature list")
	fs.Parse(args)

	if *org == "" {
		return fmt.Errorf("-org is required")
	}

	privStr := *priv
	if privStr == "" {
		s, err := readStdin("Paste private key (base64), end with EOF:")
		if err != nil {
			return err
		}
		privStr = s
	}
	privKey, err := license.ParsePrivateKey(privStr)
	if err != nil {
		return err
	}

	issuedAt := time.Now()
	if *issued != "" {
		issuedAt, err = time.Parse(time.RFC3339, *issued)
		if err != nil {
			return fmt.Errorf("-issued: %w", err)
		}
	}
	if *days < 1 {
		return fmt.Errorf("-days must be >= 1")
	}
	expiresAt := issuedAt.AddDate(0, 0, *days)

	var feats []string
	if *features != "" {
		for f := range strings.SplitSeq(*features, ",") {
			if f = strings.TrimSpace(f); f != "" {
				feats = append(feats, f)
			}
		}
	}

	lic := license.License{
		ID:           *id,
		Organization: *org,
		IssuedAt:     issuedAt,
		ExpiresAt:    expiresAt,
		Features:     feats,
	}
	signed, err := lic.Sign(privKey)
	if err != nil {
		return err
	}
	encoded, err := signed.Encode()
	if err != nil {
		return err
	}

	pretty, _ := json.MarshalIndent(signed, "", "  ")
	fmt.Println("License:")
	fmt.Println(string(pretty))
	fmt.Println("\nIssuedAt: ", signed.License.IssuedAt.Format(time.RFC3339))
	fmt.Println("ExpiresAt:", signed.License.ExpiresAt.Format(time.RFC3339))
	fmt.Println("\nEncoded license (distribute this to the client):")
	fmt.Println(encoded)
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pub := fs.String("pub", "", "public key (base64)")
	licStr := fs.String("license", "", "encoded license (base64); empty to read from stdin")
	fs.Parse(args)

	if *pub == "" {
		return fmt.Errorf("-pub is required")
	}
	pubKey, err := license.ParsePublicKey(*pub)
	if err != nil {
		return err
	}

	encoded := *licStr
	if encoded == "" {
		s, err := readStdin("Paste encoded license, end with EOF:")
		if err != nil {
			return err
		}
		encoded = s
	}
	signed, err := license.Decode(encoded)
	if err != nil {
		return err
	}
	if err := license.Verify(signed, pubKey); err != nil {
		return err
	}

	pretty, _ := json.MarshalIndent(signed.License, "", "  ")
	fmt.Println("License is valid:")
	fmt.Println(string(pretty))
	fmt.Println("IssuedAt: ", signed.License.IssuedAt.Format(time.RFC3339))
	fmt.Println("ExpiresAt:", signed.License.ExpiresAt.Format(time.RFC3339))
	return nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "HTTP listen address")
	fs.Parse(args)

	srv := web.NewServer()
	fmt.Fprintf(os.Stderr, "cc-license web UI listening on http://localhost%s\n", *addr)
	return http.ListenAndServe(*addr, srv.Routes())
}

func readStdin(prompt string) (string, error) {
	if isTerminal(os.Stdin) {
		fmt.Fprintln(os.Stderr, prompt)
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

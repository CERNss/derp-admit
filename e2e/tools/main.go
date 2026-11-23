// Command e2etool is the small helper the e2e rig runs inside its "tools"
// container. It uses only the Go standard library so the image builds without
// downloading modules or Alpine packages.
//
//	e2etool pki DIR HOSTNAME          create a throwaway CA and a server cert for HOSTNAME (once)
//	e2etool api METHOD PATH [BODY]    call the verifier ($API_BASE), Bearer $ADMIN_KEY on /admin paths
//	e2etool tmpl TEMPLATE             render a Go text/template over the JSON read from stdin
//	e2etool shortkey nodekey:HEX      print derper's short form of a node key ("[AbCdE]")
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: e2etool pki|api|tmpl|shortkey ...")
	}
	var err error
	switch os.Args[1] {
	case "pki":
		err = cmdPKI(os.Args[2:])
	case "api":
		err = cmdAPI(os.Args[2:])
	case "tmpl":
		err = cmdTmpl(os.Args[2:])
	case "shortkey":
		err = cmdShortKey(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "e2etool:", msg)
	os.Exit(1)
}

func cmdPKI(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: pki DIR HOSTNAME")
	}
	dir, host := args[0], args[1]
	caPath := filepath.Join(dir, "ca.crt")
	crtPath := filepath.Join(dir, host+".crt")
	keyPath := filepath.Join(dir, host+".key")
	if _, err := os.Stat(crtPath); err == nil {
		fmt.Println("pki: already present in", dir)
		return nil
	}
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "derp-admit e2e throwaway CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(7 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// The CA private key is never written anywhere: nothing else can be signed.
	// The leaf key is world-readable on purpose: it lives in a throwaway Docker
	// volume and derper runs as a non-root user.
	if err := writePEM(caPath, "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}
	if err := writePEM(crtPath, "CERTIFICATE", leafDER, 0o644); err != nil {
		return err
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", leafKeyDER, 0o644); err != nil {
		return err
	}
	fmt.Printf("pki: CA and certificate for %s written to %s\n", host, dir)
	return nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		panic(err)
	}
	return n
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func cmdAPI(args []string) error {
	if len(args) < 2 || len(args) > 3 {
		return fmt.Errorf("usage: api METHOD PATH [BODY]")
	}
	base := os.Getenv("API_BASE")
	if base == "" {
		base = "http://verifier:8080"
	}
	var body io.Reader
	if len(args) == 3 {
		body = strings.NewReader(args[2])
	}
	req, err := http.NewRequest(args[0], base+args[1], body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.HasPrefix(args[1], "/admin") && os.Getenv("ADMIN_KEY") != "" {
		req.Header.Set("Authorization", "Bearer "+os.Getenv("ADMIN_KEY"))
	}
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	os.Stdout.Write(bytes.TrimSpace(out))
	fmt.Println()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("%s %s: HTTP %d", args[0], args[1], res.StatusCode)
	}
	return nil
}

func cmdTmpl(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: tmpl TEMPLATE < json")
	}
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("decode stdin: %w", err)
	}
	t, err := template.New("t").Option("missingkey=zero").Funcs(template.FuncMap{
		"json": func(x any) (string, error) {
			b, err := json.Marshal(x)
			return string(b), err
		},
		"str": func(x any) string {
			if x == nil {
				return ""
			}
			return fmt.Sprint(x)
		},
		"hasPrefix": strings.HasPrefix,
		"contains":  strings.Contains,
		"join": func(xs []any, sep string) string {
			parts := make([]string, 0, len(xs))
			for _, x := range xs {
				parts = append(parts, fmt.Sprint(x))
			}
			return strings.Join(parts, sep)
		},
	}).Parse(args[0])
	if err != nil {
		return err
	}
	return t.Execute(os.Stdout, v)
}

func cmdShortKey(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: shortkey nodekey:HEX")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(args[0], "nodekey:"))
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("invalid node key %q", args[0])
	}
	// Same as tailscale.com/types/key.NodePublic.ShortString.
	fmt.Printf("[%s]\n", base64.StdEncoding.EncodeToString(raw[:4])[:5])
	return nil
}

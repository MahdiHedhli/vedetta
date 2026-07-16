// Command dbkeygen generates an ed25519 keypair for signing device-DB bundles. It prints
// the private key (store it as the VEDETTA_DB_SIGNING_KEY CI secret) and the public key
// (paste it into trustedPublicKeyBase64 in backend/internal/dbupdate/trustkey.go). The
// private key is printed once and never written to disk — capture it into your secret store
// immediately.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dbkeygen:", err)
		os.Exit(1)
	}
	fmt.Println("# Device-DB signing keypair (ed25519). Treat the PRIVATE key as a secret.")
	fmt.Println("#   1) Store PRIVATE_KEY as the CI secret VEDETTA_DB_SIGNING_KEY.")
	fmt.Println("#   2) Paste PUBLIC_KEY into trustedPublicKeyBase64 (backend/internal/dbupdate/trustkey.go).")
	fmt.Printf("PRIVATE_KEY=%s\n", base64.StdEncoding.EncodeToString(priv))
	fmt.Printf("PUBLIC_KEY=%s\n", base64.StdEncoding.EncodeToString(pub))
}

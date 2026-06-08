package vault_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/gigmcp/gigmcp/internal/vault"
)

func newKEK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	v, err := vault.New(newKEK(t))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	secret := []byte("ghp_realtoken_value")
	box, err := v.Encrypt(secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(box, secret) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := v.Decrypt(box)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestEncryptIsNondeterministic(t *testing.T) {
	v, _ := vault.New(newKEK(t))
	a, _ := v.Encrypt([]byte("x"))
	b, _ := v.Encrypt([]byte("x"))
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of same plaintext are identical — nonce reuse")
	}
}

func TestWrongKEKFails(t *testing.T) {
	v1, _ := vault.New(newKEK(t))
	v2, _ := vault.New(newKEK(t))
	box, _ := v1.Encrypt([]byte("secret"))
	if _, err := v2.Decrypt(box); err == nil {
		t.Fatal("decrypt with wrong KEK must fail")
	}
}

func TestTamperFails(t *testing.T) {
	v, _ := vault.New(newKEK(t))
	box, _ := v.Encrypt([]byte("secret"))
	box[len(box)-1] ^= 0xff
	if _, err := v.Decrypt(box); err == nil {
		t.Fatal("tampered ciphertext must fail authentication")
	}
}

func TestNewRejectsBadKEK(t *testing.T) {
	if _, err := vault.New(make([]byte, 16)); err == nil {
		t.Fatal("KEK must be 32 bytes")
	}
}

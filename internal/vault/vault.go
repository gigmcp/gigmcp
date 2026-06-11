// Package vault provides envelope encryption for credentials at rest
// (DESIGN.md decision #15). Each secret gets a fresh random data key (DEK);
// the DEK is wrapped by the master key (KEK) supplied at startup. A DB dump
// without the KEK is useless. Ciphertext layout (all XChaCha20-Poly1305):
//
//	[1 byte version=1]
//	[24 byte nonce_kek][len-prefixed wrapped-DEK = Seal(KEK, nonce_kek, DEK)]
//	[24 byte nonce_dek][ciphertext = Seal(DEK, nonce_dek, plaintext)]
package vault

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const version = 1

// Vault encrypts/decrypts secrets using envelope encryption under a KEK.
type Vault struct {
	kek []byte
}

// New returns a Vault. kek must be exactly 32 bytes.
func New(kek []byte) (*Vault, error) {
	if len(kek) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("KEK must be %d bytes, got %d", chacha20poly1305.KeySize, len(kek))
	}
	dup := make([]byte, len(kek))
	copy(dup, kek)
	return &Vault{kek: dup}, nil
}

func seal(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, nil), nil
}

func open(key, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

// Encrypt wraps plaintext with a fresh DEK, itself wrapped by the KEK.
func (v *Vault) Encrypt(plaintext []byte) ([]byte, error) {
	dek := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	// Wipe the plaintext DEK once it has been wrapped and used to seal the
	// plaintext. Defense-in-depth: Go's GC gives no hard guarantee, but this
	// minimizes the window in which the key sits recoverable on the heap (core
	// dump / swap / memory disclosure). Placed right after creation so it fires
	// on every return path. Only the transient DEK is wiped — the returned
	// ciphertext is unaffected.
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()
	nKEK, wrapped, err := seal(v.kek, dek)
	if err != nil {
		return nil, err
	}
	nDEK, ct, err := seal(dek, plaintext)
	if err != nil {
		return nil, err
	}
	out := []byte{version}
	out = append(out, nKEK...)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(wrapped)))
	out = append(out, l[:]...)
	out = append(out, wrapped...)
	out = append(out, nDEK...)
	out = append(out, ct...)
	return out, nil
}

// Decrypt reverses Encrypt.
func (v *Vault) Decrypt(box []byte) ([]byte, error) {
	const nx = chacha20poly1305.NonceSizeX
	if len(box) < 1+nx+4 || box[0] != version {
		return nil, errors.New("vault: malformed or unsupported ciphertext")
	}
	p := 1
	nKEK := box[p : p+nx]
	p += nx
	wlen := int(binary.BigEndian.Uint32(box[p : p+4]))
	p += 4
	if wlen < 0 || p+wlen+nx > len(box) {
		return nil, errors.New("vault: truncated ciphertext")
	}
	wrapped := box[p : p+wlen]
	p += wlen
	dek, err := open(v.kek, nKEK, wrapped)
	if err != nil {
		return nil, fmt.Errorf("vault: unwrap DEK: %w", err)
	}
	// Wipe the unwrapped DEK after use. Defense-in-depth: Go's GC gives no hard
	// guarantee, but this minimizes the in-memory window for the recovered key
	// (core dump / swap / memory disclosure). Placed right after unwrap so it
	// fires even if the credential open below fails. The returned plaintext is
	// unaffected.
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()
	nDEK := box[p : p+nx]
	p += nx
	ct := box[p:]
	return open(dek, nDEK, ct)
}

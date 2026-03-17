package main

import (
	"crypto/ed25519"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
)

// ClientRequest is the message sent from the client to the server.
// It contains only the encrypted birth date — the server never sees the plaintext.
type ClientRequest struct {
	EncryptedBirthDate *rlwe.Ciphertext
}

// ServerResponse is the message sent from the server back to the client.
// It contains the encrypted result of the homomorphic age comparison and
// a session ID that links this computation to a future decryption request.
type ServerResponse struct {
	EncryptedResult *rlwe.Ciphertext
	SessionID       string
}

// DecryptionShare wraps the client's key-switch share for threshold decryption.
// It key-switches the ciphertext from the collective key toward sk=0.
// The share alone reveals nothing about the plaintext.
type DecryptionShare struct {
	Share multiparty.KeySwitchShare
}

// DecryptionRequest is sent by the client after receiving the server's response.
// It contains the blinded ciphertext (the client multiplied the server's result
// by a random factor) and the client's decryption share for that blinded
// ciphertext. The server combines it with its own share to decrypt.
type DecryptionRequest struct {
	SessionID     string
	ClientShare   *DecryptionShare
	BlindedResult *rlwe.Ciphertext
}

// Attestation is a signed JWT token proving that a client passed (or failed)
// age verification. A relying party can verify it using the server's public key.
type Attestation struct {
	// Token is the signed JWT string (header.payload.signature).
	Token string

	// Verified is the outcome: true if the client met the age threshold.
	Verified bool
}

// VerifyAttestation checks the signature on an attestation token using the
// server's Ed25519 public key. Returns the decoded claims if valid.
func VerifyAttestation(token string, publicKey ed25519.PublicKey) (*AttestationClaims, error) {
	return verifyJWT(token, publicKey)
}

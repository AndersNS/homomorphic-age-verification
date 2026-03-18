package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AttestationClaims are the JWT claims in an age-verification attestation.
type AttestationClaims struct {
	// Issuer identifies the verification server.
	Issuer string `json:"iss"`

	// Subject is the session ID linking this attestation to a specific computation.
	Subject string `json:"sub"`

	// IssuedAt is the Unix timestamp when the attestation was issued.
	IssuedAt int64 `json:"iat"`

	// ExpiresAt is the Unix timestamp when the attestation expires.
	ExpiresAt int64 `json:"exp"`

	// Verified is true if the client met the age requirement.
	Verified bool `json:"verified"`
}

// jwtHeader is the fixed JWT header for Ed25519-signed tokens.
var jwtHeader = base64URLEncode([]byte(`{"alg":"EdDSA","typ":"JWT"}`))

// signJWT creates a signed JWT from the given claims using Ed25519.
func signJWT(claims *AttestationClaims, privateKey ed25519.PrivateKey) (string, error) {
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	payload := base64URLEncode(payloadJSON)
	signingInput := jwtHeader + "." + payload

	signature := ed25519.Sign(privateKey, []byte(signingInput))
	sig := base64URLEncode(signature)

	return signingInput + "." + sig, nil
}

/*
verifyJWT verifies a JWT signature and returns the decoded claims.
It validates that the header specifies the EdDSA algorithm.
*/
func verifyJWT(token string, publicKey ed25519.PublicKey) (*AttestationClaims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Validate the header matches our expected EdDSA header.
	if parts[0] != jwtHeader {
		return nil, fmt.Errorf("invalid JWT: unexpected header (expected EdDSA)")
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT signature encoding: %w", err)
	}

	if !ed25519.Verify(publicKey, []byte(signingInput), signature) {
		return nil, fmt.Errorf("invalid JWT signature")
	}

	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload encoding: %w", err)
	}

	var claims AttestationClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid JWT claims: %w", err)
	}

	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("JWT expired at %s", time.Unix(claims.ExpiresAt, 0))
	}

	return &claims, nil
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

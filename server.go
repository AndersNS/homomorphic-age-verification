package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

/*
noiseFloodingSigma is the standard deviation for noise added during
threshold decryption. Without this, a malicious party could analyze the
other party's decryption share to extract information about their secret
key. The extra noise "floods" the share so that it reveals nothing useful
beyond what the final plaintext already reveals.
*/
const noiseFloodingSigma = 8 * rlwe.DefaultNoise

/*
Server represents the age-verification service. It performs homomorphic
computation on encrypted birth dates to determine whether a user meets
the required age requirement, without ever seeing the plaintext birth date.

In the threshold protocol, the server holds its own secret key share and
combines it with the client's decryption share to decrypt only the
computation result — never the original birth date.

The client applies a random blinding factor before sending its decryption
share, so the server only ever sees a blinded result. This prevents the
server from recovering the exact birth date while still allowing it to
determine pass/fail (by checking which half of the plaintext modulus the
blinded value falls in).

After verification, the server issues signed attestation tokens (JWTs)
that relying parties can independently verify.
*/
type Server struct {
	params         bgv.Parameters
	encoder        *bgv.Encoder
	secretKey      *rlwe.SecretKey // server's secret key share
	currentDate    time.Time
	ageRequirement uint64
	cks            multiparty.KeySwitchProtocol

	// Ed25519 signing key for attestation tokens.
	signingKey ed25519.PrivateKey
	edPubKey   ed25519.PublicKey

	/*
		sessions tracks pending verification sessions. Each session records
		the server's encrypted result so it can verify the client's blinding
		proof when the decryption request comes back. (In a real deployment
		this is stored server-side, keyed by session cookie or similar.)
	*/
	sessions sync.Map // map[sessionID]session
}

type session struct {
	createdAt       time.Time
	encryptedResult *rlwe.Ciphertext // the server's original encrypted result
}

// sessionTTL is how long a session remains valid.
const sessionTTL = 5 * time.Minute

// attestationTTL is how long a signed attestation token remains valid.
const attestationTTL = 24 * time.Hour

/*
NewServer creates a new Server that verifies users are at least ageRequirement
years old relative to the given currentDate. It takes the server's secret key
share (generated during threshold setup) and generates a fresh Ed25519 key
pair for signing attestation tokens.
*/
func NewServer(params bgv.Parameters, currentDate time.Time, ageRequirement uint64, secretKey *rlwe.SecretKey) (*Server, error) {
	encoder := bgv.NewEncoder(params)

	// Generate Ed25519 signing key pair.
	edPubKey, edPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key: %w", err)
	}

	cks, err := multiparty.NewKeySwitchProtocol(params, ring.DiscreteGaussian{
		Sigma: noiseFloodingSigma,
		Bound: noiseFloodingSigma * 6,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create key switch protocol: %w", err)
	}

	return &Server{
		params:         params,
		encoder:        encoder,
		secretKey:      secretKey,
		currentDate:    currentDate,
		ageRequirement: uint64(ageRequirement),
		cks:            cks,
		signingKey:     edPrivKey,
		edPubKey:       edPubKey,
	}, nil
}

/*
PublicKey returns the server's Ed25519 public key. Relying parties use this
to verify attestation tokens.
*/
func (s *Server) PublicKey() ed25519.PublicKey {
	return s.edPubKey
}

/*
VerifyAge performs homomorphic age verification on the encrypted birth date
in the request. It computes (reqBirthdate - birthDay), giving an
encrypted difference that is non-negative if and only if the user is old
enough.
a - b = Enc(A- B)
The encrypted result remains under the collective key (sk_client + sk_server).
The client must blind it and send a decryption share to complete the protocol.
*/
func (s *Server) VerifyAge(request *ClientRequest) (*ServerResponse, error) {
	if request == nil || request.EncryptedBirthDate == nil {
		return nil, fmt.Errorf("request or encrypted birth date is nil")
	}

	// The latest birth date (in days since epoch) that qualifies.
	reqDate := s.currentDate.AddDate(-int(s.ageRequirement), 0, 0)
	reqBirthdate := dateToDays(reqDate)

	evaluator := bgv.NewEvaluator(s.params, nil)

	// Encode reqBirthdate into a plaintext vector.
	reqBirthdayVector := make([]uint64, s.params.MaxSlots())
	reqBirthdayVector[0] = reqBirthdate

	reqBirthdayPlaintext := bgv.NewPlaintext(s.params, s.params.MaxLevel())
	if err := s.encoder.Encode(reqBirthdayVector, reqBirthdayPlaintext); err != nil {
		return nil, fmt.Errorf("failed to encode max birth date: %w", err)
	}

	resultCiphertext := request.EncryptedBirthDate.CopyNew()

	/*
		Compute (reqBirthdate - birthDay) homomorphically.
		BGV doesn't have a direct subtraction of (plaintext - ciphertext),
		so we negate the ciphertext first (multiply by p-1, which is -1 mod p)
		and then add the plaintext.
	*/
	if err := evaluator.Mul(resultCiphertext, s.params.PlaintextModulus()-1, resultCiphertext); err != nil {
		return nil, fmt.Errorf("failed to negate ciphertext: %w", err)
	}

	// Add reqBirthdate to get Enc(reqBirthdate - birthDay).
	if err := evaluator.Add(resultCiphertext, reqBirthdayPlaintext, resultCiphertext); err != nil {
		return nil, fmt.Errorf("failed to add plaintext: %w", err)
	}

	// Create a session to track the pending verification.
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	s.sessions.Store(sessionID, session{
		createdAt:       time.Now(),
		encryptedResult: resultCiphertext.CopyNew(),
	})

	return &ServerResponse{
		EncryptedResult: resultCiphertext,
		SessionID:       sessionID,
	}, nil
}

/*
CompleteVerification receives the client's blinded ciphertext, decryption
share, and blinding proof. It verifies the ZK proof to ensure the blinded
ciphertext is a valid scalar multiple of the server's original encrypted
result, then combines decryption shares to decrypt the blinded result,
determines pass/fail, and issues a signed attestation.

The client blinds the result with a random factor before sending it, so the
server only sees r * (reqBirthday - birthDay). This preserves the sign
(positive = pass, negative = fail) but hides the exact difference, preventing
the server from recovering the birth date.

The blinding proof prevents a malicious client from substituting a fabricated
ciphertext that would decrypt to a favorable value.

This is the key security property: the server decrypts the result itself
rather than trusting the client's claim. Neither party can decrypt alone.
*/
func (s *Server) CompleteVerification(req *DecryptionRequest) (*Attestation, error) {
	if req == nil {
		return nil, fmt.Errorf("decryption request is nil")
	}

	if req.BlindedResult == nil {
		return nil, fmt.Errorf("blinded ciphertext is nil")
	}

	if req.BlindingProof == nil {
		return nil, fmt.Errorf("blinding proof is nil")
	}

	// Look up and consume the session (one-time use).
	val, ok := s.sessions.LoadAndDelete(req.SessionID)
	if !ok {
		return nil, fmt.Errorf("unknown or already-used session ID")
	}

	sess := val.(session)

	// Check session hasn't expired.
	if time.Since(sess.createdAt) > sessionTTL {
		return nil, fmt.Errorf("session expired")
	}

	/*
		Verify the blinding proof: the client must prove that BlindedResult
		is a scalar multiple of the original EncryptedResult from VerifyAge,
		without revealing the scalar.
	*/
	valid, err := VerifyBlindingProof(s.params, sess.encryptedResult, req.BlindedResult, req.BlindingProof)
	if err != nil {
		return nil, fmt.Errorf("failed to verify blinding proof: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("blinding proof verification failed: client may have tampered with the ciphertext")
	}

	ct := req.BlindedResult

	/*
		Generate the server's decryption share (key-switch from sk_server toward sk=0).
		See the comment in client.go BlindAndGenShare for how this works.
	*/
	zero := rlwe.NewSecretKey(s.params)
	serverShare := s.cks.AllocateShare(ct.Level())
	s.cks.GenShare(s.secretKey, zero, ct, &serverShare)

	// Aggregate both decryption shares.
	combined := s.cks.AllocateShare(ct.Level())
	if err := s.cks.AggregateShares(req.ClientShare.Share, serverShare, &combined); err != nil {
		return nil, fmt.Errorf("failed to aggregate decryption shares: %w", err)
	}

	/*
		Apply the combined key-switch: moves the ciphertext from being encrypted
		under (sk_client + sk_server) to being encrypted under sk=0.
		Decrypting with sk=0 is trivial — just read the constant term.
	*/
	ctSwitched := bgv.NewCiphertext(s.params, 1, ct.Level())
	s.cks.KeySwitch(ct, combined, ctSwitched)

	decryptor := rlwe.NewDecryptor(s.params, zero)
	pt := decryptor.DecryptNew(ctSwitched)
	resultVector := make([]uint64, s.params.MaxSlots())
	if err := s.encoder.Decode(pt, resultVector); err != nil {
		return nil, fmt.Errorf("failed to decode result: %w", err)
	}

	blindedResult := resultVector[0]

	/*
		Determine pass/fail from the decrypted value.

		BGV arithmetic is modular (mod p), so there are no "negative numbers".
		 values in [0, p/2] represent non-negative results (user is old enough)
		 values in (p/2, p) represent negative results (too young).
		This works because our values are small relative to p,
		and the blinding factor is bounded to keep r*diff within [0, p/2].
	*/
	halfModulus := s.params.PlaintextModulus() / 2
	verified := blindedResult <= halfModulus

	// Sign the attestation (as a jwt).
	now := time.Now()
	claims := &AttestationClaims{
		Issuer:    "homomorphic-age-verification",
		Subject:   req.SessionID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(attestationTTL).Unix(),
		Verified:  verified,
	}

	token, err := signJWT(claims, s.signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign attestation: %w", err)
	}

	return &Attestation{
		Token:    token,
		Verified: verified, // just for convenience, token is enough
	}, nil
}

// generateSessionID returns a random hex string
func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

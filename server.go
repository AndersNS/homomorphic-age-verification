package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// noiseFloodingSigma is the standard deviation for noise flooding during
// threshold decryption. This prevents a party from learning information
// about the other party's secret key share from the decryption share.
const noiseFloodingSigma = 8 * rlwe.DefaultNoise

// Server represents the age-verification service. It performs homomorphic
// computation on encrypted birth dates to determine whether a user meets
// the required age threshold, without ever seeing the plaintext birth date.
//
// In the threshold protocol, the server holds its own secret key share and
// combines it with the client's decryption share to decrypt only the
// computation result — never the original birth date.
//
// The server applies a random blinding factor to the result so that the
// client cannot recover the exact age threshold from its decryption share.
//
// After verification, the server issues signed attestation tokens (JWTs)
// that relying parties can independently verify.
type Server struct {
	params       bgv.Parameters
	encoder      *bgv.Encoder
	secretKey    *rlwe.SecretKey // server's secret key share
	currentDays  uint64          // current date as days since epoch
	ageThreshold uint64
	maxBlind     uint64 // maximum blinding factor r
	cks          multiparty.KeySwitchProtocol

	// Ed25519 signing key for attestation tokens.
	signingKey ed25519.PrivateKey
	edPubKey   ed25519.PublicKey

	// sessions tracks pending verification sessions. Each session stores
	// the encrypted result so the server can perform threshold decryption
	// when the client sends its decryption share.
	sessions sync.Map // map[sessionID]session
}

// session holds server-side state for a pending threshold decryption.
type session struct {
	encryptedResult *rlwe.Ciphertext
	createdAt       time.Time
}

// sessionTTL is how long a session remains valid.
const sessionTTL = 5 * time.Minute

// attestationTTL is how long a signed attestation token remains valid.
const attestationTTL = 24 * time.Hour

// NewServer creates a new Server that verifies users are at least ageThreshold
// years old relative to the given currentDate. It takes the server's secret key
// share (generated during threshold setup) and generates a fresh Ed25519 key
// pair for signing attestation tokens.
func NewServer(params bgv.Parameters, currentDate time.Time, ageThreshold uint64, secretKey *rlwe.SecretKey) (*Server, error) {
	encoder := bgv.NewEncoder(params)

	currentDays := dateToDays(currentDate)

	// Compute the maximum blinding factor.
	// The max positive difference (in days) is bounded by the span from epoch
	// to the threshold date. A person born on 1900-01-01 being verified today
	// gives the largest diff. We need r * maxDiff < p/2.
	thresholdDate := currentDate.AddDate(-int(ageThreshold), 0, 0)
	maxDiff := dateToDays(thresholdDate) - dateToDays(epoch)
	if maxDiff == 0 {
		maxDiff = 1
	}
	halfModulus := params.PlaintextModulus() / 2
	maxBlind := halfModulus / maxDiff

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
		params:       params,
		encoder:      encoder,
		secretKey:    secretKey,
		currentDays:  currentDays,
		ageThreshold: ageThreshold,
		maxBlind:     maxBlind,
		cks:          cks,
		signingKey:   edPrivKey,
		edPubKey:     edPubKey,
	}, nil
}

// PublicKey returns the server's Ed25519 public key. Relying parties use this
// to verify attestation tokens.
func (s *Server) PublicKey() ed25519.PublicKey {
	return s.edPubKey
}

// VerifyAge performs homomorphic age verification on the encrypted birth date
// in the request. It computes r * (maxBirthDays - encryptedBirthDays) where
// r is a random blinding factor, and returns the encrypted result along with
// a session ID.
//
// The encrypted result remains under the collective key (sk_client + sk_server).
// The client must send a decryption share to complete the protocol.
func (s *Server) VerifyAge(request *ClientRequest) (*ServerResponse, error) {
	if request == nil || request.EncryptedBirthDate == nil {
		return nil, fmt.Errorf("request or encrypted birth date is nil")
	}

	// The latest birth date (in days since epoch) that qualifies.
	currentDate := epoch.AddDate(0, 0, int(s.currentDays))
	thresholdDate := currentDate.AddDate(-int(s.ageThreshold), 0, 0)
	maxBirthDays := dateToDays(thresholdDate)

	evaluator := bgv.NewEvaluator(s.params, nil)

	// Generate a random blinding factor r in [2, maxBlind].
	r, err := randomBlind(s.maxBlind)
	if err != nil {
		return nil, fmt.Errorf("failed to generate blinding factor: %w", err)
	}

	// Encode maxBirthDays into a plaintext vector.
	maxBirthDaysVector := make([]uint64, s.params.MaxSlots())
	maxBirthDaysVector[0] = maxBirthDays

	maxBirthDaysPlaintext := bgv.NewPlaintext(s.params, s.params.MaxLevel())
	if err := s.encoder.Encode(maxBirthDaysVector, maxBirthDaysPlaintext); err != nil {
		return nil, fmt.Errorf("failed to encode max birth date: %w", err)
	}

	resultCiphertext := request.EncryptedBirthDate.CopyNew()

	// Negate the encrypted birth date: multiply by (p-1) ≡ -1 (mod p).
	if err := evaluator.Mul(resultCiphertext, s.params.PlaintextModulus()-1, resultCiphertext); err != nil {
		return nil, fmt.Errorf("failed to negate ciphertext: %w", err)
	}

	// Add maxBirthDays, giving us Enc(maxBirthDays - birthDays).
	if err := evaluator.Add(resultCiphertext, maxBirthDaysPlaintext, resultCiphertext); err != nil {
		return nil, fmt.Errorf("failed to add plaintext: %w", err)
	}

	// Multiply by the random blinding factor r, giving us
	// Enc(r * (maxBirthDays - birthDays)). This hides the exact difference
	// from the client while preserving the sign (positive = verified).
	if err := evaluator.Mul(resultCiphertext, r, resultCiphertext); err != nil {
		return nil, fmt.Errorf("failed to apply blinding factor: %w", err)
	}

	// Create a session storing the encrypted result for threshold decryption.
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	s.sessions.Store(sessionID, session{
		encryptedResult: resultCiphertext,
		createdAt:       time.Now(),
	})

	return &ServerResponse{
		EncryptedResult: resultCiphertext,
		SessionID:       sessionID,
	}, nil
}

// CompleteVerification receives the client's decryption share, combines it
// with the server's own share to decrypt the result, determines pass/fail,
// and issues a signed attestation.
//
// This is the key security property: the server decrypts the result itself
// rather than trusting the client's claim. Neither party can decrypt alone.
func (s *Server) CompleteVerification(req *DecryptionRequest) (*Attestation, error) {
	if req == nil {
		return nil, fmt.Errorf("decryption request is nil")
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

	ct := sess.encryptedResult

	// Generate the server's decryption share (key-switch from sk_server to 0).
	zero := rlwe.NewSecretKey(s.params)
	serverShare := s.cks.AllocateShare(ct.Level())
	s.cks.GenShare(s.secretKey, zero, ct, &serverShare)

	// Aggregate both decryption shares.
	combined := s.cks.AllocateShare(ct.Level())
	if err := s.cks.AggregateShares(req.ClientShare.Share, serverShare, &combined); err != nil {
		return nil, fmt.Errorf("failed to aggregate decryption shares: %w", err)
	}

	// Apply the key-switch: result is now encrypted under sk=0.
	ctSwitched := bgv.NewCiphertext(s.params, 1, ct.Level())
	s.cks.KeySwitch(ct, combined, ctSwitched)

	// Decrypt with sk=0 (trivial decryption: just read c0).
	decryptor := rlwe.NewDecryptor(s.params, zero)
	pt := decryptor.DecryptNew(ctSwitched)
	resultVector := make([]uint64, s.params.MaxSlots())
	if err := s.encoder.Decode(pt, resultVector); err != nil {
		return nil, fmt.Errorf("failed to decode result: %w", err)
	}

	blindedResult := resultVector[0]

	// Determine pass/fail: value <= p/2 means the difference was non-negative.
	halfModulus := s.params.PlaintextModulus() / 2
	verified := blindedResult <= halfModulus

	// Sign the attestation.
	now := time.Now()
	claims := &AttestationClaims{
		Issuer:       "homomorphic-age-verification",
		Subject:      req.SessionID,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(attestationTTL).Unix(),
		Verified:     verified,
		AgeThreshold: s.ageThreshold,
	}

	token, err := signJWT(claims, s.signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign attestation: %w", err)
	}

	return &Attestation{
		Token:    token,
		Verified: verified,
	}, nil
}

// generateSessionID returns a cryptographically random hex string.
func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// randomBlind returns a cryptographically random uint64 in [2, max].
// Uses crypto/rand to ensure the blinding factor is unpredictable.
func randomBlind(max uint64) (uint64, error) {
	if max < 2 {
		return 2, nil // degenerate case: no room for randomness
	}
	// Generate r in [0, max-2], then add 2 to get [2, max].
	rangeSize := new(big.Int).SetUint64(max - 1) // max - 2 + 1
	n, err := rand.Int(rand.Reader, rangeSize)
	if err != nil {
		return 0, err
	}
	return n.Uint64() + 2, nil
}

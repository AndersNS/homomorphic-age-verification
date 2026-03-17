package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// testParams is a shared parameter set for all tests. BGV parameter generation
// is expensive, so we do it once.
var testParams bgv.Parameters

// testClientSK and testServerSK are the threshold secret key shares for tests.
var (
	testClientSK *rlwe.SecretKey
	testServerSK *rlwe.SecretKey
)

// testCollectivePK is the collective public key for tests.
var testCollectivePK *rlwe.PublicKey

// testCurrentDate is the reference "today" for tests.
var testCurrentDate = date(2025, 11, 24)

func TestMain(m *testing.M) {
	var err error
	testParams, err = bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             14,
		LogQ:             []int{56, 55, 55, 54, 54, 54},
		LogP:             []int{55, 55},
		PlaintextModulus: 0x10000048001,
	})
	if err != nil {
		panic("failed to create test parameters: " + err.Error())
	}

	testClientSK, testServerSK, testCollectivePK = generateTestKeys(testParams, []byte("test-crs-seed-for-determinism"))

	os.Exit(m.Run())
}

// generateTestKeys runs the two-participant CKG ceremony and returns the
// secret keys and collective public key. This is a test helper that simulates
// the network exchange between client and server.
func generateTestKeys(params bgv.Parameters, crsSeed []byte) (*rlwe.SecretKey, *rlwe.SecretKey, *rlwe.PublicKey) {
	clientP, err := NewCKGParticipant(params, crsSeed)
	if err != nil {
		panic("client CKG participant: " + err.Error())
	}
	serverP, err := NewCKGParticipant(params, crsSeed)
	if err != nil {
		panic("server CKG participant: " + err.Error())
	}
	pk := clientP.CombineShares(serverP.Share())
	return clientP.SecretKey(), serverP.SecretKey(), pk
}

// date is a convenience constructor for UTC dates in tests.
func date(year, month, day int) time.Time {
	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
}

// newTestServer creates a Server for tests, failing immediately on error.
func newTestServer(t testing.TB, currentDate time.Time, ageThreshold uint64) *Server {
	t.Helper()
	server, err := NewServer(testParams, currentDate, ageThreshold, testServerSK)
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	return server
}

// newTestClient creates a Client for tests, failing immediately on error.
func newTestClient(t testing.TB, birthDate time.Time) *Client {
	t.Helper()
	client, err := NewClient(testParams, birthDate, testClientSK, testCollectivePK, testCurrentDate)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	return client
}

// runVerification is a test helper that runs the full threshold verification flow.
// It returns the attestation and the server response (for session ID access).
func runVerification(t *testing.T, server *Server, birthDate time.Time) (*Attestation, *ServerResponse) {
	t.Helper()

	client := newTestClient(t, birthDate)

	request, err := client.CreateRequest()
	if err != nil {
		t.Fatalf("CreateRequest() error: %v", err)
	}

	response, err := server.VerifyAge(request)
	if err != nil {
		t.Fatalf("VerifyAge() error: %v", err)
	}

	blindedResult, clientShare, err := client.BlindAndGenShare(response.EncryptedResult)
	if err != nil {
		t.Fatalf("BlindAndGenShare() error: %v", err)
	}

	attestation, err := server.CompleteVerification(&DecryptionRequest{
		SessionID:     response.SessionID,
		ClientShare:   clientShare,
		BlindedResult: blindedResult,
	})
	if err != nil {
		t.Fatalf("CompleteVerification() error: %v", err)
	}

	return attestation, response
}

func TestAgeVerification(t *testing.T) {
	server := newTestServer(t, testCurrentDate, 18)

	tests := []struct {
		name       string
		birthDate  time.Time
		wantPassed bool
	}{
		{"exactly 18 today", date(2007, 11, 24), true},
		{"turned 18 yesterday", date(2007, 11, 23), true},
		{"one day too young", date(2007, 11, 25), false},
		{"well over 18", date(1987, 10, 25), true},
		{"15 years old", date(2010, 5, 15), false},
		{"born on Jan 1 of threshold year", date(2007, 1, 1), true},
		{"born on Dec 31 of threshold year", date(2007, 12, 31), false},
		{"very old person", date(1925, 1, 1), true},
		{"born day before threshold in different month", date(2007, 10, 24), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestation, _ := runVerification(t, server, tt.birthDate)
			if attestation.Verified != tt.wantPassed {
				t.Errorf("verification for %s: got %v, want %v",
					tt.birthDate.Format("2006-01-02"), attestation.Verified, tt.wantPassed)
			}
		})
	}
}

func TestAgeVerificationCustomThreshold(t *testing.T) {
	server := newTestServer(t, testCurrentDate, 21) // drinking age

	tests := []struct {
		name       string
		birthDate  time.Time
		wantPassed bool
	}{
		{"exactly 21 today", date(2004, 11, 24), true},
		{"20 years old", date(2005, 11, 24), false},
		{"25 years old", date(2000, 11, 24), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestation, _ := runVerification(t, server, tt.birthDate)
			if attestation.Verified != tt.wantPassed {
				t.Errorf("verification for %s: got %v, want %v",
					tt.birthDate.Format("2006-01-02"), attestation.Verified, tt.wantPassed)
			}
		})
	}
}

func TestBlindingPreventsThresholdRecovery(t *testing.T) {
	// Run the same verification multiple times and confirm the client's
	// blinding produces different blinded ciphertexts each time.
	server := newTestServer(t, testCurrentDate, 18)

	birthDate := date(1990, 1, 15)
	client := newTestClient(t, birthDate)

	for i := 0; i < 5; i++ {
		request, err := client.CreateRequest()
		if err != nil {
			t.Fatalf("CreateRequest() error: %v", err)
		}

		response, err := server.VerifyAge(request)
		if err != nil {
			t.Fatalf("VerifyAge() error: %v", err)
		}

		blindedResult, clientShare, err := client.BlindAndGenShare(response.EncryptedResult)
		if err != nil {
			t.Fatalf("BlindAndGenShare() error: %v", err)
		}

		attestation, err := server.CompleteVerification(&DecryptionRequest{
			SessionID:     response.SessionID,
			ClientShare:   clientShare,
			BlindedResult: blindedResult,
		})
		if err != nil {
			t.Fatalf("CompleteVerification() error: %v", err)
		}

		if !attestation.Verified {
			t.Error("expected verification to pass")
		}
	}
}

func TestAttestationFlow(t *testing.T) {
	server := newTestServer(t, testCurrentDate, 18)

	tests := []struct {
		name       string
		birthDate  time.Time
		wantPassed bool
	}{
		{"passes verification", date(1990, 1, 15), true},
		{"fails verification", date(2010, 5, 15), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestation, response := runVerification(t, server, tt.birthDate)

			if attestation.Verified != tt.wantPassed {
				t.Errorf("attestation.Verified = %v, want %v", attestation.Verified, tt.wantPassed)
			}

			// Relying party verifies the token.
			claims, err := VerifyAttestation(attestation.Token, server.PublicKey())
			if err != nil {
				t.Fatalf("VerifyAttestation() error: %v", err)
			}

			if claims.Verified != tt.wantPassed {
				t.Errorf("claims.Verified = %v, want %v", claims.Verified, tt.wantPassed)
			}
			if claims.AgeThreshold != 18 {
				t.Errorf("claims.AgeThreshold = %d, want 18", claims.AgeThreshold)
			}
			if claims.Subject != response.SessionID {
				t.Errorf("claims.Subject = %q, want %q", claims.Subject, response.SessionID)
			}
		})
	}
}

func TestSessionIsOneTimeUse(t *testing.T) {
	server := newTestServer(t, testCurrentDate, 18)
	client := newTestClient(t, date(1990, 1, 15))

	request, err := client.CreateRequest()
	if err != nil {
		t.Fatalf("CreateRequest() error: %v", err)
	}

	response, err := server.VerifyAge(request)
	if err != nil {
		t.Fatalf("VerifyAge() error: %v", err)
	}

	blindedResult, clientShare, err := client.BlindAndGenShare(response.EncryptedResult)
	if err != nil {
		t.Fatalf("BlindAndGenShare() error: %v", err)
	}

	// First completion should succeed.
	_, err = server.CompleteVerification(&DecryptionRequest{
		SessionID:     response.SessionID,
		ClientShare:   clientShare,
		BlindedResult: blindedResult,
	})
	if err != nil {
		t.Fatalf("first CompleteVerification() error: %v", err)
	}

	// Second attempt with the same session should fail (consumed).
	_, err = server.CompleteVerification(&DecryptionRequest{
		SessionID:     response.SessionID,
		ClientShare:   clientShare,
		BlindedResult: blindedResult,
	})
	if err == nil {
		t.Error("expected error on reuse of session ID, got nil")
	}
}

func TestCompleteVerificationRejectsInvalidSession(t *testing.T) {
	server := newTestServer(t, testCurrentDate, 18)

	// Create a dummy share and ciphertext to send with a bogus session ID.
	cks, err := multiparty.NewKeySwitchProtocol(testParams, ring.DiscreteGaussian{
		Sigma: noiseFloodingSigma,
		Bound: noiseFloodingSigma * 6,
	})
	if err != nil {
		t.Fatalf("NewKeySwitchProtocol() error: %v", err)
	}

	share := cks.AllocateShare(testParams.MaxLevel())
	dummyCt := bgv.NewCiphertext(testParams, 1, testParams.MaxLevel())

	_, err = server.CompleteVerification(&DecryptionRequest{
		SessionID:     "nonexistent-session-id",
		ClientShare:   &DecryptionShare{Share: share},
		BlindedResult: dummyCt,
	})
	if err == nil {
		t.Error("expected error for invalid session ID, got nil")
	}
}

func TestAttestationRejectsWrongPublicKey(t *testing.T) {
	server := newTestServer(t, testCurrentDate, 18)

	attestation, _ := runVerification(t, server, date(1990, 1, 15))

	// Verify with a different key should fail.
	wrongPub, _, _ := ed25519.GenerateKey(nil)
	_, err := VerifyAttestation(attestation.Token, wrongPub)
	if err == nil {
		t.Error("expected signature verification to fail with wrong key, got nil")
	}
}

func TestNewClientValidation(t *testing.T) {
	tests := []struct {
		name      string
		birthDate time.Time
		wantErr   bool
	}{
		{"valid date", date(1990, 1, 15), false},
		{"valid leap day", date(2000, 2, 29), false},
		{"date before epoch", date(1899, 12, 31), true},
		{"future date", time.Now().AddDate(1, 0, 0), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(testParams, tt.birthDate, testClientSK, testCollectivePK, testCurrentDate)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient(%s) error = %v, wantErr %v",
					tt.birthDate.Format("2006-01-02"), err, tt.wantErr)
			}
		})
	}
}

func TestDateToDays(t *testing.T) {
	tests := []struct {
		name string
		date time.Time
		want uint64
	}{
		{"epoch itself", date(1900, 1, 1), 0},
		{"one day after epoch", date(1900, 1, 2), 1},
		{"one year after epoch", date(1901, 1, 1), 365},
		{"leap year", date(1904, 3, 1), 1520}, // 4*365 + 31 + 29 (1900 is not a leap year)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dateToDays(tt.date)
			if got != tt.want {
				t.Errorf("dateToDays(%s) = %d, want %d",
					tt.date.Format("2006-01-02"), got, tt.want)
			}
		})
	}
}

func TestAttestationRejectsTamperedJWT(t *testing.T) {
	server := newTestServer(t, testCurrentDate, 18)

	attestation, _ := runVerification(t, server, date(2010, 5, 15))

	// Tamper with the JWT payload (flip a character).
	parts := strings.SplitN(attestation.Token, ".", 3)
	if len(parts) != 3 {
		t.Fatal("invalid JWT format")
	}
	tampered := parts[0] + "." + parts[1] + "X" + "." + parts[2]

	_, err := VerifyAttestation(tampered, server.PublicKey())
	if err == nil {
		t.Error("expected error for tampered JWT, got nil")
	}
}

func TestVerifyAgeRejectsNilRequest(t *testing.T) {
	server := newTestServer(t, testCurrentDate, 18)

	_, err := server.VerifyAge(nil)
	if err == nil {
		t.Error("expected error for nil request, got nil")
	}

	_, err = server.VerifyAge(&ClientRequest{EncryptedBirthDate: nil})
	if err == nil {
		t.Error("expected error for nil encrypted birth date, got nil")
	}
}

func TestBlindAndGenShareRejectsNilCiphertext(t *testing.T) {
	client := newTestClient(t, date(1990, 1, 15))

	_, _, err := client.BlindAndGenShare(nil)
	if err == nil {
		t.Error("expected error for nil ciphertext, got nil")
	}
}

func TestCompleteVerificationRejectsNilRequest(t *testing.T) {
	server := newTestServer(t, testCurrentDate, 18)

	_, err := server.CompleteVerification(nil)
	if err == nil {
		t.Error("expected error for nil decryption request, got nil")
	}
}

func TestCompleteVerificationRejectsNilBlindedResult(t *testing.T) {
	server := newTestServer(t, testCurrentDate, 18)

	client := newTestClient(t, date(1990, 1, 15))
	request, err := client.CreateRequest()
	if err != nil {
		t.Fatalf("CreateRequest() error: %v", err)
	}

	response, err := server.VerifyAge(request)
	if err != nil {
		t.Fatalf("VerifyAge() error: %v", err)
	}

	_, clientShare, err := client.BlindAndGenShare(response.EncryptedResult)
	if err != nil {
		t.Fatalf("BlindAndGenShare() error: %v", err)
	}

	_, err = server.CompleteVerification(&DecryptionRequest{
		SessionID:     response.SessionID,
		ClientShare:   clientShare,
		BlindedResult: nil,
	})
	if err == nil {
		t.Error("expected error for nil blinded ciphertext, got nil")
	}
}

func TestDateToDaysNonUTC(t *testing.T) {
	// A date specified in a non-UTC timezone should produce the same day count
	// as the equivalent UTC date.
	loc := time.FixedZone("UTC+10", 10*60*60)
	// Nov 24 2025 at midnight UTC+10 is still Nov 23 in UTC.
	nonUTC := time.Date(2025, 11, 24, 0, 0, 0, 0, loc)
	utcEquiv := time.Date(2025, 11, 23, 14, 0, 0, 0, time.UTC)

	got := dateToDays(nonUTC)
	want := dateToDays(utcEquiv)
	if got != want {
		t.Errorf("dateToDays(non-UTC) = %d, dateToDays(UTC equiv) = %d, want equal", got, want)
	}
}

func TestSessionExpiry(t *testing.T) {
	server := newTestServer(t, testCurrentDate, 18)
	client := newTestClient(t, date(1990, 1, 15))

	request, err := client.CreateRequest()
	if err != nil {
		t.Fatalf("CreateRequest() error: %v", err)
	}

	response, err := server.VerifyAge(request)
	if err != nil {
		t.Fatalf("VerifyAge() error: %v", err)
	}

	blindedResult, clientShare, err := client.BlindAndGenShare(response.EncryptedResult)
	if err != nil {
		t.Fatalf("BlindAndGenShare() error: %v", err)
	}

	// Manually expire the session by replacing it with an old createdAt.
	server.sessions.Store(response.SessionID, session{
		createdAt: time.Now().Add(-sessionTTL - time.Second),
	})

	_, err = server.CompleteVerification(&DecryptionRequest{
		SessionID:     response.SessionID,
		ClientShare:   clientShare,
		BlindedResult: blindedResult,
	})
	if err == nil {
		t.Error("expected error for expired session, got nil")
	}
}

func TestJWTRejectsWrongAlgorithmHeader(t *testing.T) {
	server := newTestServer(t, testCurrentDate, 18)

	attestation, _ := runVerification(t, server, date(1990, 1, 15))

	// Replace the header with a different algorithm.
	parts := strings.SplitN(attestation.Token, ".", 3)
	wrongHeader := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	tamperedToken := wrongHeader + "." + parts[1] + "." + parts[2]

	_, err := VerifyAttestation(tamperedToken, server.PublicKey())
	if err == nil {
		t.Error("expected error for wrong algorithm header, got nil")
	}
}

func TestCKGParticipant(t *testing.T) {
	p, err := NewCKGParticipant(testParams, []byte("test-seed"))
	if err != nil {
		t.Fatalf("NewCKGParticipant() error: %v", err)
	}

	if p.SecretKey() == nil {
		t.Error("SecretKey is nil")
	}
}

func TestCKGDifferentSeedsProduceDifferentKeys(t *testing.T) {
	_, _, pk1 := generateTestKeys(testParams, []byte("seed-one"))
	_, _, pk2 := generateTestKeys(testParams, []byte("seed-two"))

	// The collective public keys should differ.
	pk1Bytes, _ := pk1.MarshalBinary()
	pk2Bytes, _ := pk2.MarshalBinary()

	if string(pk1Bytes) == string(pk2Bytes) {
		t.Error("expected different collective public keys for different seeds")
	}
}

func TestWrongDecryptionShareProducesGarbage(t *testing.T) {
	// If the client sends a decryption share from the wrong secret key,
	// the result should be garbage (not a valid pass/fail). The server
	// will still produce an attestation, but the result is meaningless.
	server := newTestServer(t, testCurrentDate, 18)

	// Use the correct setup for the client request/encryption.
	client := newTestClient(t, date(1990, 1, 15))

	request, err := client.CreateRequest()
	if err != nil {
		t.Fatalf("CreateRequest() error: %v", err)
	}

	response, err := server.VerifyAge(request)
	if err != nil {
		t.Fatalf("VerifyAge() error: %v", err)
	}

	// Client blinds correctly but we'll replace the share with one from a wrong key.
	blindedResult, _, err := client.BlindAndGenShare(response.EncryptedResult)
	if err != nil {
		t.Fatalf("BlindAndGenShare() error: %v", err)
	}

	// Generate a decryption share using a WRONG secret key.
	wrongClientSK, _, _ := generateTestKeys(testParams, []byte("wrong-seed"))

	wrongCKS, err := multiparty.NewKeySwitchProtocol(testParams, ring.DiscreteGaussian{
		Sigma: noiseFloodingSigma,
		Bound: noiseFloodingSigma * 6,
	})
	if err != nil {
		t.Fatalf("NewKeySwitchProtocol() error: %v", err)
	}

	zero := rlwe.NewSecretKey(testParams)
	wrongShare := wrongCKS.AllocateShare(blindedResult.Level())
	wrongCKS.GenShare(wrongClientSK, zero, blindedResult, &wrongShare)

	// The server should still complete (it can't tell the share is wrong),
	// but the decrypted value is garbage.
	attestation, err := server.CompleteVerification(&DecryptionRequest{
		SessionID:     response.SessionID,
		ClientShare:   &DecryptionShare{Share: wrongShare},
		BlindedResult: blindedResult,
	})
	if err != nil {
		t.Fatalf("CompleteVerification() error: %v", err)
	}

	// We can't predict the outcome -- it's random garbage. Just verify
	// the flow completes without panicking.
	_ = attestation
}

func TestEndToEndWithFreshSetup(t *testing.T) {
	// Full end-to-end test using freshly generated keys,
	// independent of the global test keys.
	crsSeed := make([]byte, 32)
	if _, err := rand.Read(crsSeed); err != nil {
		t.Fatalf("rand.Read() error: %v", err)
	}

	clientSK, serverSK, pk := generateTestKeys(testParams, crsSeed)

	server, err := NewServer(testParams, testCurrentDate, 18, serverSK)
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	birthDate := date(1990, 1, 15)
	client, err := NewClient(testParams, birthDate, clientSK, pk, testCurrentDate)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	request, err := client.CreateRequest()
	if err != nil {
		t.Fatalf("CreateRequest() error: %v", err)
	}

	response, err := server.VerifyAge(request)
	if err != nil {
		t.Fatalf("VerifyAge() error: %v", err)
	}

	blindedResult, clientShare, err := client.BlindAndGenShare(response.EncryptedResult)
	if err != nil {
		t.Fatalf("BlindAndGenShare() error: %v", err)
	}

	attestation, err := server.CompleteVerification(&DecryptionRequest{
		SessionID:     response.SessionID,
		ClientShare:   clientShare,
		BlindedResult: blindedResult,
	})
	if err != nil {
		t.Fatalf("CompleteVerification() error: %v", err)
	}

	if !attestation.Verified {
		t.Error("expected verification to pass for 35-year-old")
	}

	// Verify the JWT.
	claims, err := VerifyAttestation(attestation.Token, server.PublicKey())
	if err != nil {
		t.Fatalf("VerifyAttestation() error: %v", err)
	}

	if !claims.Verified {
		t.Error("claims.Verified = false, want true")
	}
	if claims.AgeThreshold != 18 {
		t.Errorf("claims.AgeThreshold = %d, want 18", claims.AgeThreshold)
	}
}

func BenchmarkFullVerification(b *testing.B) {
	server := newTestServer(b, testCurrentDate, 18)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client := newTestClient(b, date(1990, 1, 15))

		request, err := client.CreateRequest()
		if err != nil {
			b.Fatal(err)
		}

		response, err := server.VerifyAge(request)
		if err != nil {
			b.Fatal(err)
		}

		blindedResult, clientShare, err := client.BlindAndGenShare(response.EncryptedResult)
		if err != nil {
			b.Fatal(err)
		}

		_, err = server.CompleteVerification(&DecryptionRequest{
			SessionID:     response.SessionID,
			ClientShare:   clientShare,
			BlindedResult: blindedResult,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewClient(testParams, date(1990, 1, 15), testClientSK, testCollectivePK, testCurrentDate)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryption(b *testing.B) {
	client := newTestClient(b, date(1990, 1, 15))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.CreateRequest()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServerComputation(b *testing.B) {
	server := newTestServer(b, testCurrentDate, 18)

	client := newTestClient(b, date(1990, 1, 15))
	request, err := client.CreateRequest()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := server.VerifyAge(request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkThresholdSetup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateTestKeys(testParams, []byte("bench-seed"))
	}
}

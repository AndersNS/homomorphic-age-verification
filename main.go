package main

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func main() {
	fmt.Println("============================================")
	fmt.Println("  Homomorphic Age Verification Demo")
	fmt.Println("  (Threshold Decryption Protocol)")
	fmt.Println("============================================")
	fmt.Println()
	fmt.Println("Protocol: Client encrypts birth date under a collective public key.")
	fmt.Println("Server computes age comparison homomorphically on the encrypted data.")
	fmt.Println("Client blinds the result so the server can't recover the exact birth date.")
	fmt.Println("Neither party can decrypt alone — both must contribute decryption shares.")
	fmt.Println("The server combines shares, determines pass/fail, and issues a signed JWT.")
	fmt.Println()

	// Setup BGV encryption parameters (shared between client and server).
	//
	// LogN controls the polynomial ring size (security level and capacity).
	// LogQ/LogP define the ciphertext modulus chain (precision vs. noise budget).
	// PlaintextModulus is the modulus for plaintext arithmetic — a 41-bit
	// NTT-friendly prime, large enough to hold day-count dates (~16 bits)
	// multiplied by a blinding factor (~24 bits) without overflow.
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             14,
		LogQ:             []int{56, 55, 55, 54, 54, 54},
		LogP:             []int{55, 55},
		PlaintextModulus: 0x10000048001,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create parameters: %v", err))
	}

	// Step 1: Threshold key generation ceremony.
	// Each party creates a CKG participant independently (in separate processes).
	// They exchange only their CKG shares — secret keys never leave their owner.
	fmt.Println("--- Threshold Setup ---")
	crsSeed := make([]byte, 32)
	if _, err := rand.Read(crsSeed); err != nil {
		panic(fmt.Sprintf("failed to generate CRS seed: %v", err))
	}

	// Client process: generate secret key + CKG share.
	clientParticipant, err := NewCKGParticipant(params, crsSeed)
	if err != nil {
		panic(fmt.Sprintf("failed to create client CKG participant: %v", err))
	}

	// Server process: generate secret key + CKG share.
	serverParticipant, err := NewCKGParticipant(params, crsSeed)
	if err != nil {
		panic(fmt.Sprintf("failed to create server CKG participant: %v", err))
	}

	// Exchange shares (in a real deployment, sent over the network).
	// Both parties combine shares to get the same collective public key.
	collectivePK := clientParticipant.CombineShares(serverParticipant.Share())

	fmt.Println("  Collective public key generated (2-of-2 threshold)")
	fmt.Println()

	currentDate := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC) // Hardcode the current date to make testing easier ("Today" is the 24 th of November 2026)

	ageThreshold := uint64(18) // Age threshold only know known by server, but sent as param to make it eaiser to test
	server, err := NewServer(params, currentDate, ageThreshold, serverParticipant.SecretKey())
	if err != nil {
		panic(fmt.Sprintf("failed to create server: %v", err))
	}

	testCases := []struct {
		birthDate   time.Time
		description string
		shouldPass  bool
	}{
		{time.Date(2007, 11, 25, 0, 0, 0, 0, time.UTC), "Born Nov 25, 2007 (one day too young)", false},
		{time.Date(2007, 11, 24, 0, 0, 0, 0, time.UTC), "Born Nov 24, 2007 (exactly 18 today)", true},
		{time.Date(2007, 11, 23, 0, 0, 0, 0, time.UTC), "Born Nov 23, 2007 (turned 18 yesterday)", true},
		{time.Date(1987, 10, 25, 0, 0, 0, 0, time.UTC), "Born Oct 25, 1987 (38 years old)", true},
		{time.Date(2010, 5, 15, 0, 0, 0, 0, time.UTC), "Born May 15, 2010 (15 years old)", false},
	}

	for _, tc := range testCases {
		fmt.Println("--------------------------------------------")
		fmt.Printf("Test: %s\n", tc.description)

		// Step 2: Client encrypts birth date under the collective public key.
		client, err := NewClient(params, tc.birthDate, clientParticipant.SecretKey(), collectivePK, currentDate)
		if err != nil {
			panic(fmt.Sprintf("failed to create client: %v", err))
		}

		request, err := client.CreateRequest()
		if err != nil {
			panic(fmt.Sprintf("failed to create request: %v", err))
		}

		// Step 3: Server computes homomorphically (blinded age comparison).
		response, err := server.VerifyAge(request)
		if err != nil {
			panic(fmt.Sprintf("failed to verify age: %v", err))
		}

		// Step 4: Client blinds the result and generates its decryption share.
		blindedResult, clientShare, err := client.BlindAndGenShare(response.EncryptedResult)
		if err != nil {
			panic(fmt.Sprintf("failed to blind and generate share: %v", err))
		}

		// Step 5: Server combines decryption shares, determines pass/fail,
		// and issues a signed attestation.
		attestation, err := server.CompleteVerification(&DecryptionRequest{
			SessionID:     response.SessionID,
			ClientShare:   clientShare,
			BlindedResult: blindedResult,
		})
		if err != nil {
			panic(fmt.Sprintf("failed to complete verification: %v", err))
		}

		result := "REJECTED"
		if attestation.Verified {
			result = "VERIFIED"
		}

		status := "PASS"
		if attestation.Verified != tc.shouldPass {
			status = "FAIL"
		}

		fmt.Printf("  Result: %s | Expected: %v | %s\n", result, tc.shouldPass, status)

		// Step 6: Relying party verifies the attestation token.
		claims, err := VerifyAttestation(attestation.Token, server.PublicKey())
		if err != nil {
			panic(fmt.Sprintf("failed to verify attestation: %v", err))
		}

		fmt.Printf("  Attestation: verified=%v, age>=%d\n",
			claims.Verified, claims.AgeThreshold)
	}

	fmt.Println("--------------------------------------------")
	fmt.Println("Done.")
}

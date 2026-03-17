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
	fmt.Println("Server computes age comparison homomorphically and blinds the result.")
	fmt.Println("Neither party can decrypt alone — both must contribute decryption shares.")
	fmt.Println("The server combines shares, determines pass/fail, and issues a signed JWT.")
	fmt.Println()

	// Setup cryptographic parameters (shared between client and server).
	// PlaintextModulus is a 41-bit NTT-friendly prime, large enough to
	// support ~24 bits of blinding randomness on day-count encoded dates.
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
	// In a real deployment this is an interactive protocol over a network.
	// Both parties contribute to the collective public key without revealing
	// their secret key shares.
	fmt.Println("--- Threshold Setup ---")
	crsSeed := make([]byte, 32)
	if _, err := rand.Read(crsSeed); err != nil {
		panic(fmt.Sprintf("failed to generate CRS seed: %v", err))
	}

	setup, err := GenerateThresholdSetup(params, crsSeed)
	if err != nil {
		panic(fmt.Sprintf("failed threshold setup: %v", err))
	}
	fmt.Println("  Collective public key generated (2-of-2 threshold)")
	fmt.Println()

	currentDate := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)
	ageThreshold := uint64(18)
	server, err := NewServer(params, currentDate, ageThreshold, setup.ServerSecretKey)
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
		client, err := NewClient(params, tc.birthDate, setup.ClientSecretKey, setup.CollectivePublicKey)
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

		// Step 4: Client generates its decryption share.
		clientShare, err := client.GenDecryptionShare(response.EncryptedResult)
		if err != nil {
			panic(fmt.Sprintf("failed to generate decryption share: %v", err))
		}

		// Step 5: Server combines decryption shares, determines pass/fail,
		// and issues a signed attestation.
		attestation, err := server.CompleteVerification(&DecryptionRequest{
			SessionID:   response.SessionID,
			ClientShare: clientShare,
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

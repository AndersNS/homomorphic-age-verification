package main

import (
	"flag"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func ageVerification() {
	fmt.Println("============================================")
	fmt.Println("Homomorphic Age Verification")
	fmt.Println("============================================")
	fmt.Println()
	fmt.Println("Protocol: Client encrypts birth date, server verifies age >= 18")
	fmt.Println("without learning the actual birth date")
	fmt.Println()

	// Setup cryptographic parameters (shared by both client and server, for simplicity)
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             14,
		LogQ:             []int{56, 55, 55, 54, 54, 54},
		LogP:             []int{55, 55},
		PlaintextModulus: 0x3ee0001,
	})
	if err != nil {
		panic(err)
	}

	currentDate := uint64(20251124) // November 24, 2025, just hard code for the demo
	server := NewServer(params, currentDate)

	testCases := []struct {
		birthDate   uint64
		description string
		shouldPass  bool
	}{
		{20071125, "Person born Nov 25, 2007 (day after threshold)", false},
		{20071124, "Person born Nov 24, 2007 (exactly 18 today)", true},
		{20071123, "Person born Nov 23, 2007 (turned 18 yesterday)", true},
		{19871025, "Person born Oct 25, 1987 (👴)", true},
		{20100515, "Person born May 15, 2010 (15 years old)", false},
	}

	for _, tc := range testCases {
		fmt.Println("============================================")
		fmt.Println("============================================")
		fmt.Printf("Example: %s\n", tc.description)
		fmt.Println("============================================")
		fmt.Println("============================================")
		fmt.Println()

		fmt.Println("--- CLIENT SIDE ---")
		testClient := NewClient(params, tc.birthDate)
		fmt.Printf("[CLIENT] My birth date: %d\n", tc.birthDate)

		testRequest, err := testClient.CreateRequest()
		if err != nil {
			panic(err)
		}

		fmt.Println(">>> Sending to server...")
		fmt.Println()

		fmt.Println("--- SERVER SIDE ---")
		testResponse, err := server.VerifyAge(testRequest)
		if err != nil {
			panic(err)
		}

		fmt.Println("<<< Sending response to client...")
		fmt.Println()

		fmt.Println("--- CLIENT SIDE (processing response)---")
		testVerified, err := testClient.ProcessResponse(testResponse)
		if err != nil {
			panic(err)
		}

		fmt.Printf("[DEMO] Verification correct: %t\n", testVerified == tc.shouldPass)
		fmt.Println()
	}
}

func main() {
	flag.Parse()
	ageVerification()
}

package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type Server struct {
	params       bgv.Parameters
	encoder      *bgv.Encoder
	currentDate  uint64
	ageThreshold uint64
}

func NewServer(params bgv.Parameters, currentDate uint64) *Server {
	encoder := bgv.NewEncoder(params)

	return &Server{
		params:       params,
		encoder:      encoder,
		currentDate:  currentDate,
		ageThreshold: 18,
	}
}

func (s *Server) VerifyAge(request *ClientRequest) (*ServerResponse, error) {
	fmt.Println("[SERVER] Received verification request")

	// Someone is >= ageThreshold if their birth date <= (currentDate - ageThreshold years)
	currentYear := s.currentDate / 10000
	currentMonthDay := s.currentDate % 10000
	thresholdYear := currentYear - s.ageThreshold
	maxBirthDate := thresholdYear*10000 + currentMonthDay

	fmt.Printf("[SERVER] Maximum birth date for age %d: %d\n", s.ageThreshold, maxBirthDate)

	evaluator := bgv.NewEvaluator(s.params, nil)

	maxBirthDateVector := make([]uint64, s.params.MaxSlots())
	maxBirthDateVector[0] = maxBirthDate

	maxBirthDatePlaintext := bgv.NewPlaintext(s.params, s.params.MaxLevel())
	// Convert the maxBirthDate to plaintext so we can add it to the ciphertext later
	if err := s.encoder.Encode(maxBirthDateVector, maxBirthDatePlaintext); err != nil {
		return nil, fmt.Errorf("failed to encode max birth date: %w", err)
	}

	fmt.Println("[SERVER] Computing: (MaxBirthDate - EncryptedBirthDate)")

	resultCiphertext := request.EncryptedBirthDate.CopyNew()

	// Negate the encrypted birth date: -clientBirthDate
	if err := evaluator.Mul(resultCiphertext, s.params.PlaintextModulus()-1, resultCiphertext); err != nil {
		return nil, fmt.Errorf("failed to negate ciphertext: %w", err)
	}

	// Add maxBirthDate: maxBirthDate - clientBirthDate
	if err := evaluator.Add(resultCiphertext, maxBirthDatePlaintext, resultCiphertext); err != nil {
		return nil, fmt.Errorf("failed to add plaintext: %w", err)
	}

	fmt.Println("[SERVER] Homomorphic computation complete")
	fmt.Println("[SERVER] Sending encrypted result back to client")

	return &ServerResponse{
		EncryptedResult: resultCiphertext,
	}, nil
}

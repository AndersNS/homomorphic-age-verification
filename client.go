package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type Client struct {
	params    bgv.Parameters
	encoder   *bgv.Encoder
	secretKey *rlwe.SecretKey
	publicKey *rlwe.PublicKey
	birthDate uint64
}

func NewClient(params bgv.Parameters, birthDate uint64) *Client {
	encoder := bgv.NewEncoder(params)

	kgen := rlwe.NewKeyGenerator(params)
	secretKey, publicKey := kgen.GenKeyPairNew()

	return &Client{
		params:    params,
		encoder:   encoder,
		secretKey: secretKey,
		publicKey: publicKey,
		birthDate: birthDate,
	}
}

func (c *Client) CreateRequest() (*ClientRequest, error) {
	fmt.Println("[CLIENT] Encrypting birth date...")

	encryptor := rlwe.NewEncryptor(c.params, c.secretKey)

	// Encode birth date into a vector
	birthDateVector := make([]uint64, c.params.MaxSlots())
	birthDateVector[0] = c.birthDate

	birthDatePlaintext := bgv.NewPlaintext(c.params, c.params.MaxLevel())
	if err := c.encoder.Encode(birthDateVector, birthDatePlaintext); err != nil {
		return nil, fmt.Errorf("failed to encode birth date: %w", err)
	}

	encryptedBirthDate, err := encryptor.EncryptNew(birthDatePlaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt birth date: %w", err)
	}

	fmt.Println("[CLIENT] Birth date encrypted successfully")
	fmt.Printf("[CLIENT] Sending request to server (PublicKey + EncryptedBirthDate)\n")

	return &ClientRequest{
		PublicKey:          c.publicKey,
		EncryptedBirthDate: encryptedBirthDate,
	}, nil
}

func (c *Client) ProcessResponse(response *ServerResponse) (bool, error) {
	fmt.Println("[CLIENT] Received response from server")
	fmt.Println("[CLIENT] Decrypting result...")

	decryptor := rlwe.NewDecryptor(c.params, c.secretKey)

	resultPlaintext := decryptor.DecryptNew(response.EncryptedResult)
	resultVector := make([]uint64, c.params.MaxSlots())
	if err := c.encoder.Decode(resultPlaintext, resultVector); err != nil {
		return false, fmt.Errorf("failed to decode result: %w", err)
	}

	difference := resultVector[0]

	// In modular arithmetic, if the birth date was <= maxBirthDate,
	// the result will be a small positive number (or 0)
	// If birth date > maxBirthDate, result wraps around to a large number
	// So if diference is bigger than half the modulus, we consider it as negative number, and vice versa
	halfModulus := c.params.PlaintextModulus() / 2
	isVerified := difference <= halfModulus

	fmt.Printf("[CLIENT] Decrypted result: %d\n", difference)
	fmt.Printf("[CLIENT] Verification result: ")
	if isVerified {
		fmt.Println("✓ VERIFIED - You are at least 18 years old")
	} else {
		fmt.Println("✗ REJECTED - You are under 18 years old")
	}

	return isVerified, nil
}

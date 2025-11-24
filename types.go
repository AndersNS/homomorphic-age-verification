package main

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

type ClientRequest struct {
	PublicKey          *rlwe.PublicKey
	EncryptedBirthDate *rlwe.Ciphertext
}

type ServerResponse struct {
	EncryptedResult *rlwe.Ciphertext
}

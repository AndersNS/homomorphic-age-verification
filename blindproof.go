package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

/*
BlindingProof is a non-interactive zero-knowledge proof (Schnorr/Sigma
protocol via Fiat-Shamir) that the blinded ciphertext B is a valid scalar
multiple of the original ciphertext A. That is, B = r * A for some secret
scalar r, without revealing r.

This prevents a malicious client from substituting a fabricated ciphertext
during the blinding step of the threshold decryption protocol.

The proof works as follows:
 1. Commit: the prover picks a random k, computes commitment T = k * A
 2. Challenge: e = H(A, B, T) via Fiat-Shamir (non-interactive)
 3. Response: z = k + e * r (computed over the integers)
 4. Verify: the verifier checks z * A == T + e * B for each polynomial
    component of the ciphertext, in each RNS subring.
*/
type BlindingProof struct {
	// Commitment is T = k * A, where k is a random nonce.
	Commitment *rlwe.Ciphertext

	// Response is z = k + e * r, where e is the Fiat-Shamir challenge.
	Response *big.Int
}

/*
commitmentBits is the bit-length of the random nonce k used in the proof.

Why 256 bits? The nonce k must be large enough to "statistically hide" the
secret blinding factor r when computing z = k + e * r. If k were too small,
an attacker could recover r from z. The hiding margin is:

	|k| - |e * r| = 256 - (128 + 24) = 104 bits of statistical security

where |e| = 128 bits (challenge) and |r| ~ 24 bits (blinding factor).
This means even an adversary with unbounded computation sees z as
essentially random — r is hidden by over 100 bits of entropy.
*/
const commitmentBits = 256

/*
challengeBits is the bit-length of the Fiat-Shamir challenge.
128 bits provides computational soundness — a cheating prover would need
to guess a 128-bit value correctly, which has negligible probability.
*/
const challengeBits = 128

/*
GenerateBlindingProof produces a ZK proof that blindedCyphertext = r * originalCyphertext,
where r is the (secret) blinding factor the client used.

The proof is non-interactive via the Fiat-Shamir transform: the challenge
is derived by hashing the original ciphertext, the blinded ciphertext, and
the commitment together.

Only the proof (commitment T and response z) is sent to the server.
The blinding factor r is never transmitted or revealed.
*/
func GenerateBlindingProof(
	params bgv.Parameters,
	originalCt *rlwe.Ciphertext,
	blindedCt *rlwe.Ciphertext,
	r uint64,
) (*BlindingProof, error) {
	/*
		Get the polynomial ring at the ciphertext's current level.
		"Level" refers to how many moduli remain in the RNS chain — it
		decreases as homomorphic operations consume noise budget.
	*/
	ringQ := params.RingQ().AtLevel(blindedCt.Level())

	/*
		Step 1: Sample a random nonce k from [0, 2^commitmentBits).
		This is the randomness that hides r in the response z = k + e*r.
		Think of it like a one-time pad: k masks r so that z looks random.
	*/
	kMax := new(big.Int).Lsh(big.NewInt(1), commitmentBits)
	k, err := rand.Int(rand.Reader, kMax)
	if err != nil {
		return nil, fmt.Errorf("failed to sample commitment nonce: %w", err)
	}

	/*
		Step 2: Compute commitment T = k * A (component-wise in the ring).
		A BGV ciphertext has multiple polynomial components (typically 2:
		ct[0] and ct[1]). We multiply each component by k independently.
		This is the "envelope" we commit to before the challenge is known.
	*/
	commitment := originalCt.CopyNew()
	for i := 0; i < originalCt.Degree()+1; i++ {
		ringQ.MulScalarBigint(originalCt.Value[i], k, commitment.Value[i])
	}

	/*
		Step 3: Compute Fiat-Shamir challenge e = H(A, B, T).
		By deriving the challenge from a hash of all public values, we
		simulate a random challenge from a verifier — but without needing
		any interaction. The prover can't cheat because they committed to
		T before e was determined (T is an input to the hash).
	*/
	e, err := computeChallenge(originalCt, blindedCt, commitment)
	if err != nil {
		return nil, fmt.Errorf("failed to compute challenge: %w", err)
	}

	/*
		Step 4: Compute response z = k + e * r (over the integers).
		This is computed over the integers (not modular arithmetic) to
		avoid any information leakage from modular reduction.
	*/
	rBig := new(big.Int).SetUint64(r)
	z := new(big.Int).Mul(e, rBig)
	z.Add(z, k)

	return &BlindingProof{
		Commitment: commitment,
		Response:   z,
	}, nil
}

/*
VerifyBlindingProof checks a ZK proof that blindedCt = r * originalCt for
some scalar r, without learning r.

It verifies the Schnorr relation: z * A == T + e * B, where:
  - A is the original ciphertext (from the server's computation)
  - B is the blinded ciphertext (sent by the client)
  - T is the commitment (part of the proof)
  - z is the response (part of the proof)
  - e is recomputed from H(A, B, T)

Why this equation proves B = r * A:

	LHS = z * A = (k + e*r) * A = k*A + e*r*A
	RHS = T + e*B = k*A + e*B
	LHS == RHS  iff  e*r*A == e*B  iff  B == r*A

If the client used a different blinding factor (or a fabricated ciphertext),
the equation will not hold and the proof is rejected.
*/
func VerifyBlindingProof(
	params bgv.Parameters,
	originalCt *rlwe.Ciphertext,
	blindedCt *rlwe.Ciphertext,
	proof *BlindingProof,
) (bool, error) {
	if proof == nil || proof.Commitment == nil || proof.Response == nil {
		return false, fmt.Errorf("proof is nil or incomplete")
	}

	ringQ := params.RingQ().AtLevel(blindedCt.Level())

	/*
		Recompute the challenge from the same inputs the prover used.
		If the prover tampered with anything, the challenge will differ
		and the verification equation will fail.
	*/
	e, err := computeChallenge(originalCt, blindedCt, proof.Commitment)
	if err != nil {
		return false, fmt.Errorf("failed to recompute challenge: %w", err)
	}

	/*
		Check: z * A[i] == T[i] + e * B[i]  for each polynomial component i.

		A BGV ciphertext has Degree()+1 polynomial components (typically 2).
		Each polynomial is represented in RNS form (split across multiple
		sub-rings modulo different primes). The MulScalarBigint and Add
		operations work across all RNS sub-rings simultaneously, so this
		single loop verifies the relation in every sub-ring.

		We compute both sides independently and compare:
		  LHS = z * A[i]
		  RHS = T[i] + e * B[i]
	*/
	for i := 0; i < originalCt.Degree()+1; i++ {
		lhs := ringQ.NewPoly()
		ringQ.MulScalarBigint(originalCt.Value[i], proof.Response, lhs)

		rhs := ringQ.NewPoly()
		ringQ.MulScalarBigint(blindedCt.Value[i], e, rhs)
		ringQ.Add(proof.Commitment.Value[i], rhs, rhs)

		if !lhs.Equal(&rhs) {
			return false, nil
		}
	}

	return true, nil
}

/*
computeChallenge derives the Fiat-Shamir challenge by hashing the
serialized original ciphertext, blinded ciphertext, and commitment.
Returns a big.Int in [0, 2^challengeBits).

The Fiat-Shamir transform works by replacing the verifier's random
challenge with H(all public data). This is secure under the "random
oracle model" — the hash function behaves like a truly random function,
so the prover can't predict or influence the challenge after committing
to T.

The domain separator "blinding-proof-challenge-v1" ensures this hash
can't collide with hashes from other protocols that might use the same
inputs in a different context.
*/
func computeChallenge(
	originalCt *rlwe.Ciphertext,
	blindedCt *rlwe.Ciphertext,
	commitment *rlwe.Ciphertext,
) (*big.Int, error) {
	h := sha256.New()

	// Write a domain separator so different protocol contexts don't collide.
	h.Write([]byte("blinding-proof-challenge-v1"))

	origBytes, err := originalCt.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal original ciphertext: %w", err)
	}
	h.Write(origBytes)

	blindedBytes, err := blindedCt.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal blinded ciphertext: %w", err)
	}
	h.Write(blindedBytes)

	commitBytes, err := commitment.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal commitment: %w", err)
	}
	h.Write(commitBytes)

	digest := h.Sum(nil) // 32 bytes = 256 bits

	// Truncate to challengeBits (128 bits = 16 bytes).
	e := new(big.Int).SetBytes(digest[:challengeBits/8])
	return e, nil
}

package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

var epoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)

func dateToDays(t time.Time) uint64 {
	return uint64(t.UTC().Truncate(24*time.Hour).Sub(epoch) / (24 * time.Hour))
}

/*
Client represents a user who wants to prove their age without revealing
their exact birth date. It holds its secret key share and the birth date
to be verified.

In the threshold protocol, the client and server each hold a share of the
secret key. Neither party can decrypt alone — both must contribute a
decryption share to reveal a plaintext.

The client applies a random blinding factor to the server's encrypted result
before generating its decryption share. This prevents the server from
recovering the exact birth date from the decrypted value.
*/
type Client struct {
	params    bgv.Parameters
	encoder   *bgv.Encoder
	secretKey *rlwe.SecretKey              // client's secret key share
	publicKey *rlwe.PublicKey              // collective public key (encrypts under sk_client + sk_server)
	birthDays uint64                       // birth date as days since epoch
	maxBlind  uint64                       // maximum blinding factor (conservative, from public info)
	cks       multiparty.KeySwitchProtocol // for generating decryption shares
}

/*
NewClient creates a new Client for the given birth date. The collective
public key (generated during setup with the server) must be provided for
encryption. The currentDate is used to compute a conservative blinding
bound from public information only.

The birth date must be a valid time.Time in the past.
*/
func NewClient(params bgv.Parameters, birthDate time.Time, secretKey *rlwe.SecretKey, collectivePK *rlwe.PublicKey, currentDate time.Time) (*Client, error) {
	if err := validateBirthDate(birthDate); err != nil {
		return nil, fmt.Errorf("invalid birth date: %w", err)
	}

	encoder := bgv.NewEncoder(params)

	cks, err := multiparty.NewKeySwitchProtocol(params, ring.DiscreteGaussian{
		Sigma: noiseFloodingSigma,
		Bound: noiseFloodingSigma * 6,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create key switch protocol: %w", err)
	}

	/*
		Compute an upper bound for the blinding factor using only
		public information. The blinded value r * diff must stay below p/2 to
		preserve the sign convention (-/+).

		The worst-case diff is for someone born on epoch day 0 and verified
		today, giving maxDiff = dateToDays(currentDate). We set:
		  maxBlind = (p/2) / maxDiff
		This is conservative — the actual diff is always smaller — but it
		avoids leaking the age requirement (which the client must not learn).
	*/
	maxDiff := dateToDays(currentDate)
	if maxDiff == 0 {
		maxDiff = 1
	}
	halfModulus := params.PlaintextModulus() / 2
	maxBlind := halfModulus / maxDiff

	return &Client{
		params:    params,
		encoder:   encoder,
		secretKey: secretKey,
		publicKey: collectivePK,
		birthDays: dateToDays(birthDate),
		maxBlind:  maxBlind,
		cks:       cks,
	}, nil
}

/*
CreateRequest encrypts the client's birth date (as days since epoch) using
the collective public key and returns a ClientRequest for the server.
*/
func (c *Client) CreateRequest() (*ClientRequest, error) {
	encryptor := rlwe.NewEncryptor(c.params, c.publicKey)

	birthDateVector := make([]uint64, c.params.MaxSlots())
	birthDateVector[0] = c.birthDays

	birthDatePlaintext := bgv.NewPlaintext(c.params, c.params.MaxLevel())
	if err := c.encoder.Encode(birthDateVector, birthDatePlaintext); err != nil {
		return nil, fmt.Errorf("failed to encode birth date: %w", err)
	}

	encryptedBirthDate, err := encryptor.EncryptNew(birthDatePlaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt birth date: %w", err)
	}

	return &ClientRequest{
		EncryptedBirthDate: encryptedBirthDate,
	}, nil
}

/*
BlindAndGenShare blinds the server's encrypted result with a random factor,
produces a zero-knowledge proof that the blinding was applied correctly, and
generates the client's decryption share for the blinded ciphertext.

The blinding multiplies the ciphertext by a random r in [2, maxBlind],
giving Enc(r * (maxBirthDays - birthDays)). This preserves the sign
(positive = pass) but hides the exact difference from the server.

The ZK proof (a Schnorr/Sigma protocol via Fiat-Shamir) proves to the server
that the blinded ciphertext is a valid scalar multiple of the original,
preventing the client from substituting a fabricated ciphertext.

	see: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic

The decryption share is generated on the blinded ciphertext, so the server
can only decrypt r * diff, not the original diff.

Returns the blinded ciphertext, the blinding proof, and the decryption
share. All three must be sent to the server.
*/
func (c *Client) BlindAndGenShare(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, *BlindingProof, *DecryptionShare, error) {
	if ct == nil {
		return nil, nil, nil, fmt.Errorf("ciphertext is nil")
	}

	// Generate a random blinding factor r in [2, maxBlind].
	r, err := randomBlind(c.maxBlind)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate blinding factor: %w", err)
	}

	// Blind the ciphertext (still homomorphically encrypted): Enc(diff) -> Enc(r * diff).
	evaluator := bgv.NewEvaluator(c.params, nil)
	blinded := ct.CopyNew()
	if err := evaluator.Mul(blinded, r, blinded); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to apply blinding factor: %w", err)
	}

	// Generate a ZK proof that blinded = r * ct, without revealing r.
	proof, err := GenerateBlindingProof(c.params, ct, blinded, r)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate blinding proof: %w", err)
	}

	/*
		Generate the client's decryption share for the blinded ciphertext.

		In threshold decryption, each party "key-switches" from their secret
		key share toward a zero key. When all shares are combined, the
		ciphertext ends up encrypted under sk=0, which means the plaintext
		can be read directly from the ciphertext.
		Note: Only this ciphertext can be decrypted with the share generated here.
	*/
	zero := rlwe.NewSecretKey(c.params)
	share := c.cks.AllocateShare(blinded.Level())
	c.cks.GenShare(c.secretKey, zero, blinded, &share)

	return blinded, proof, &DecryptionShare{Share: share}, nil
}

// validateBirthDate checks that the given date is a plausible birth date.
func validateBirthDate(date time.Time) error {
	if date.Before(epoch) {
		return fmt.Errorf("birth date %s is before %s", date.Format("2006-01-02"), epoch.Format("2006-01-02"))
	}
	if date.After(time.Now()) {
		return fmt.Errorf("birth date %s is in the future", date.Format("2006-01-02"))
	}
	return nil
}

/*
randomBlind returns a cryptographically random uint64 in [2, max].
Uses crypto/rand to ensure the blinding factor is unpredictable.
*/
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

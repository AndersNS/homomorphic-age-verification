package main

import (
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// epoch is the reference date for converting calendar dates to day counts.
// All dates are encoded as the number of days since this epoch.
var epoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)

// dateToDays converts a calendar date to the number of days since the epoch.
// The input is normalized to UTC to avoid off-by-one errors from timezone offsets.
func dateToDays(t time.Time) uint64 {
	return uint64(t.UTC().Truncate(24*time.Hour).Sub(epoch) / (24 * time.Hour))
}

// Client represents a user who wants to prove their age without revealing
// their exact birth date. It holds its secret key share and the birth date
// to be verified.
//
// In the threshold protocol, the client and server each hold a share of the
// secret key. Neither party can decrypt alone — both must contribute a
// decryption share to reveal a plaintext.
type Client struct {
	params    bgv.Parameters
	encoder   *bgv.Encoder
	secretKey *rlwe.SecretKey              // client's secret key share
	publicKey *rlwe.PublicKey              // collective public key (encrypts under sk_client + sk_server)
	birthDays uint64                       // birth date as days since epoch
	cks       multiparty.KeySwitchProtocol // for generating decryption shares
}

// NewClient creates a new Client with a fresh secret key share for the given
// birth date. The collective public key (generated during setup with the server)
// must be provided for encryption.
//
// The birth date must be a valid time.Time in the past.
func NewClient(params bgv.Parameters, birthDate time.Time, secretKey *rlwe.SecretKey, collectivePK *rlwe.PublicKey) (*Client, error) {
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

	return &Client{
		params:    params,
		encoder:   encoder,
		secretKey: secretKey,
		publicKey: collectivePK,
		birthDays: dateToDays(birthDate),
		cks:       cks,
	}, nil
}

// CreateRequest encrypts the client's birth date (as days since epoch) using
// the collective public key and returns a ClientRequest for the server.
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

// GenDecryptionShare produces the client's decryption share for the given
// ciphertext. This share must be sent to the server, which combines it with
// its own share to decrypt the result.
//
// The share key-switches the ciphertext from the collective secret key
// (sk_client + sk_server) toward sk=0. Neither share alone reveals anything.
func (c *Client) GenDecryptionShare(ct *rlwe.Ciphertext) (*DecryptionShare, error) {
	if ct == nil {
		return nil, fmt.Errorf("ciphertext is nil")
	}

	zero := rlwe.NewSecretKey(c.params)
	share := c.cks.AllocateShare(ct.Level())
	c.cks.GenShare(c.secretKey, zero, ct, &share)

	return &DecryptionShare{
		Share: share,
	}, nil
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

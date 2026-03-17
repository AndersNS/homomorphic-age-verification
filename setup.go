package main

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// ThresholdSetup holds the results of the threshold key generation ceremony.
// Both parties must participate to produce the collective public key, but
// neither party learns the other's secret key share.
type ThresholdSetup struct {
	// ClientSecretKey is the client's secret key share.
	ClientSecretKey *rlwe.SecretKey

	// ServerSecretKey is the server's secret key share.
	ServerSecretKey *rlwe.SecretKey

	// CollectivePublicKey encrypts under the sum of both secret key shares.
	// Both shares are needed to decrypt.
	CollectivePublicKey *rlwe.PublicKey
}

// GenerateThresholdSetup performs the 2-party key generation ceremony.
// Both parties generate independent secret key shares, then collaboratively
// produce a collective public key using a common reference string (CRS).
//
// In a real deployment, this would be an interactive protocol over a network.
// Here we simulate it locally for demonstration purposes.
func GenerateThresholdSetup(params rlwe.ParameterProvider, crsSeed []byte) (*ThresholdSetup, error) {
	crs, err := sampling.NewKeyedPRNG(crsSeed)
	if err != nil {
		return nil, err
	}

	kgen := rlwe.NewKeyGenerator(params)

	// Each party generates its own secret key share independently.
	skClient := kgen.GenSecretKeyNew()
	skServer := kgen.GenSecretKeyNew()

	// Collective Public Key Generation (CKG) protocol.
	// Both parties sample the same CRP from the shared CRS and generate
	// their share. The shares are aggregated to produce a public key that
	// encrypts under (skClient + skServer).
	ckg := multiparty.NewPublicKeyGenProtocol(params)
	crp := ckg.SampleCRP(crs)

	shareClient := ckg.AllocateShare()
	shareServer := ckg.AllocateShare()
	ckg.GenShare(skClient, crp, &shareClient)
	ckg.GenShare(skServer, crp, &shareServer)

	combined := ckg.AllocateShare()
	ckg.AggregateShares(shareClient, shareServer, &combined)

	pk := rlwe.NewPublicKey(params)
	ckg.GenPublicKey(combined, crp, pk)

	return &ThresholdSetup{
		ClientSecretKey:     skClient,
		ServerSecretKey:     skServer,
		CollectivePublicKey: pk,
	}, nil
}

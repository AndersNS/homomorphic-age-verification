package main

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

/*
CKGParticipant represents one party in the Collective Key Generation (CKG)
ceremony. Each party (client and server) creates their own CKGParticipant
independently, generates a secret key and a CKG share, then sends the share
to the other party (or a coordinator) to produce the collective public key.

In a real deployment, each participant runs in a separate process/machine.
The only data exchanged is the CKG share — secret keys never leave their
owner's process.
*/
type CKGParticipant struct {
	params    rlwe.ParameterProvider
	secretKey *rlwe.SecretKey
	share     multiparty.PublicKeyGenShare
	ckg       multiparty.PublicKeyGenProtocol
	crp       multiparty.PublicKeyGenCRP
}

/*
NewCKGParticipant creates a new participant for the key generation ceremony.
The crsSeed must be the same for all participants — it's a pre-agreed random
seed used to derive the Common Reference String (CRS), which is a source of
public randomness that ensures the participants' shares are compatible.
*/
func NewCKGParticipant(params rlwe.ParameterProvider, crsSeed []byte) (*CKGParticipant, error) {
	crs, err := sampling.NewKeyedPRNG(crsSeed)
	if err != nil {
		return nil, err
	}

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	ckg := multiparty.NewPublicKeyGenProtocol(params)
	crp := ckg.SampleCRP(crs)

	// Generate this participant's CKG share from their secret key.
	share := ckg.AllocateShare()
	ckg.GenShare(sk, crp, &share)

	return &CKGParticipant{
		params:    params,
		secretKey: sk,
		share:     share,
		ckg:       ckg,
		crp:       crp,
	}, nil
}

/*
SecretKey returns the participant's secret key share. This must never be
sent to the other party.
*/
func (p *CKGParticipant) SecretKey() *rlwe.SecretKey {
	return p.secretKey
}

/*
Share returns the participant's CKG share. This is the only value that
needs to be sent to the other party (or coordinator) during setup.
It reveals nothing about the secret key.
*/
func (p *CKGParticipant) Share() multiparty.PublicKeyGenShare {
	return p.share
}

/*
CombineShares takes the other party's CKG share, aggregates it with this
participant's share, and produces the collective public key. Both parties
can call this independently — they will arrive at the same public key.

The resulting public key encrypts under (sk_party1 + sk_party2). Neither
party can decrypt alone.
*/
func (p *CKGParticipant) CombineShares(otherShare multiparty.PublicKeyGenShare) *rlwe.PublicKey {
	combined := p.ckg.AllocateShare()
	p.ckg.AggregateShares(p.share, otherShare, &combined)

	pk := rlwe.NewPublicKey(p.params)
	p.ckg.GenPublicKey(combined, p.crp, pk)
	return pk
}

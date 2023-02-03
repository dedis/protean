package protocol

import (
	"github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/onet/v3/network"
)

const ShuffleProtoName = "easyneff_shuffle"

func init() {
	network.RegisterMessages(&base.ShuffleInput{})
}

type Request struct {
	ShuffleInput base.ShuffleInput
}

type ShuffleProof struct {
	Proofs []Proof
}

// Proof is the Neff shuffle proof with a signature.
type Proof struct {
	Pairs     utils.ElGamalPairs
	Proof     []byte
	Signature []byte // on the Proof
}

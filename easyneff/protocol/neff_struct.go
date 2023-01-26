package protocol

import (
	"github.com/dedis/protean/utils"
	"go.dedis.ch/kyber/v3"
)

const ShuffleProtoName = "easyneff_shuffle"

type Request struct {
	Pairs []utils.ElGamalPair
	H     kyber.Point
}

type ShuffleProof struct {
	Proofs []Proof
}

// Proof is the Neff shuffle proof with a signature.
type Proof struct {
	Pairs     []utils.ElGamalPair
	Proof     []byte
	Signature []byte // on the Proof
}

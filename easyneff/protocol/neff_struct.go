package protocol

import (
	"crypto/sha256"
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

func (shProof *ShuffleProof) Hash() ([]byte, error) {
	h := sha256.New()
	for _, pr := range shProof.Proofs {
		for _, pair := range pr.Pairs.Pairs {
			kbuf, err := pair.K.MarshalBinary()
			if err != nil {
				return nil, err
			}
			cbuf, err := pair.C.MarshalBinary()
			if err != nil {
				return nil, err
			}
			h.Write(kbuf)
			h.Write(cbuf)
		}
		h.Write(pr.Proof)
		h.Write(pr.Signature)
	}
	return h.Sum(nil), nil
}

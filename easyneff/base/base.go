package base

import (
	"crypto/sha256"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/kyber/v3"
)

const (
	UID     string = "easyneff"
	SHUFFLE string = "shuffle"
)

type ShuffleInput struct {
	Pairs utils.ElGamalPairs
	H     kyber.Point
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

func (shInput *ShuffleInput) PrepareInputHashes() (map[string][]byte, error) {
	inputHashes := make(map[string][]byte)
	hash, err := shInput.Pairs.Hash()
	if err != nil {
		return nil, err
	}
	inputHashes["pairs"] = hash
	hash, err = utils.Hash(shInput.H)
	if err != nil {
		return nil, err
	}
	inputHashes["H"] = hash
	return inputHashes, nil
}

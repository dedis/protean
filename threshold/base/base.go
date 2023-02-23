package base

import (
	"github.com/dedis/protean/utils"
	"go.dedis.ch/kyber/v3"
)

const (
	UID string = "threshold"
	DKG string = "init_dkg"
	DEC string = "decrypt"
)

type DKGOutput struct {
	X kyber.Point
}

type DecryptInput struct {
	utils.ElGamalPairs
}

type DecryptOutput struct {
	Ps []kyber.Point
}

func (decInput *DecryptInput) PrepareHashes() (map[string][]byte, error) {
	inputHashes := make(map[string][]byte)
	hash, err := decInput.Hash()
	if err != nil {
		return nil, err
	}
	inputHashes["ciphertexts"] = hash
	return inputHashes, nil
}

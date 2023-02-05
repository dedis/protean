package base

import (
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

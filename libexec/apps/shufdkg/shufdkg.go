package shufdkg

import (
	easyneff "github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/libexec/base"
	threshold "github.com/dedis/protean/threshold/base"
	"golang.org/x/xerrors"
)

func PrepareShuffle(genInput *base.GenericInput) (*base.GenericOutput, error) {
	input, ok := genInput.I.(PrepareShufInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	shInput := easyneff.ShuffleInput{Pairs: input.Pairs, H: input.H}
	return &base.GenericOutput{O: shInput}, nil
}

func PrepareDecrypt(genInput *base.GenericInput) (*base.GenericOutput, error) {
	input, ok := genInput.I.(PrepareDecInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	shProof := input.ShufProof
	sz := len(shProof.Proofs)
	pairs := shProof.Proofs[sz-1].Pairs
	decInput := threshold.DecryptInput{ElGamalPairs: pairs}
	return &base.GenericOutput{O: decInput}, nil
}

package shufdkg

import (
	easyneff "github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/libexec/base"
	threshold "github.com/dedis/protean/threshold/base"
	"golang.org/x/xerrors"
)

func PrepareShuffle(input *base.GenericInput) (*base.GenericOutput, error) {
	prepShufInput, ok := input.I.(PrepareShufInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	shInput := easyneff.ShuffleInput{Pairs: prepShufInput.Pairs}
	return &base.GenericOutput{O: shInput}, nil
}

func PrepareDecrypt(input *base.GenericInput) (*base.GenericOutput, error) {
	prepDecInput, ok := input.I.(PrepareDecInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	shProof := prepDecInput.ShufProof
	sz := len(shProof.Proofs)
	pairs := shProof.Proofs[sz-1].Pairs
	decInput := threshold.DecryptInput{ElGamalPairs: pairs}
	return &base.GenericOutput{O: decInput}, nil
}

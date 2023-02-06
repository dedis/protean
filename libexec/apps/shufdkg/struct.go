package shufdkg

import (
	"github.com/dedis/protean/easyneff/base"
	protean "github.com/dedis/protean/utils"
)

type PrepareShufInput struct {
	Pairs protean.ElGamalPairs
}

type PrepareDecInput struct {
	ShufProof base.ShuffleProof
}

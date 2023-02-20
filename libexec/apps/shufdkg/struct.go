package shufdkg

import (
	"github.com/dedis/protean/easyneff/base"
	protean "github.com/dedis/protean/utils"
	"go.dedis.ch/kyber/v3"
)

type PrepareShufInput struct {
	Pairs protean.ElGamalPairs
	H     kyber.Point
}

type PrepareDecInput struct {
	ShufProof base.ShuffleOutput
}

package playground

import (
	"github.com/dedis/protean/threshold"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/kyber/v3"
)

type SigVerData struct {
	Data    []byte
	Sig     []byte
	Publics []kyber.Point
}

type SigVerStorage struct {
	Storage []SigVerData
}

type ReconstructRequest struct {
	NumNodes int
	Cs       []*utils.ElGamalPair
	Partials []*threshold.Partial
}

type ElGamalData struct {
	NumNodes int
	Cs       []*utils.ElGamalPair
	Partials []*threshold.Partial
	Ps       []string
}

type ElGamalStorage struct {
	Storage []ElGamalData
}

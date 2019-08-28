package sys

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

type FunctionalUnit struct {
	Type     int
	Name     string
	NumNodes int
	Roster   *onet.Roster
	Publics  []kyber.Point
	Txns     []string
}

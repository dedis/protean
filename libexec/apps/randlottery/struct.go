package randlottery

import (
	"github.com/dedis/protean/easyrand/base"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/kyber/v3"
)

type Tickets struct {
	Data []Ticket
}

type Ticket struct {
	Key kyber.Point
	Sig []byte
}

type JoinInput struct {
	Ticket Ticket
}

type JoinOutput struct {
	WS byzcoin.Arguments
}

type CloseInput struct {
	Barrier   int
	BlkHeight int
}

type CloseOutput struct {
	WS byzcoin.Arguments
}

type FinalizeInput struct {
	Round      uint64
	Randomness base.RandomnessOutput
}

type FinalizeOutput struct {
	WS byzcoin.Arguments
}

type Winner struct {
	Index int
	Key   kyber.Point
}

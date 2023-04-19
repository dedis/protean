package dkglottery

import (
	threshold "github.com/dedis/protean/threshold/base"
	protean "github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/kyber/v3"
)

type SetupInput struct {
	Pk kyber.Point
}

type SetupOutput struct {
	WS byzcoin.Arguments
}

type EncTickets struct {
	Data protean.ElGamalPairs
}

type Ticket struct {
	Data protean.ElGamalPair
}

type BatchTicket struct {
	Data protean.ElGamalPairs
}

type JoinInput struct {
	Ticket Ticket
}

type BatchJoinInput struct {
	Tickets BatchTicket
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

type PrepDecOutput struct {
	Input threshold.DecryptInput
}

type FinalizeInput struct {
	Ps []kyber.Point
}

type FinalizeOutput struct {
	WS byzcoin.Arguments
}

type DecTickets struct {
	Data [][]byte
}

type Winner struct {
	Index  int
	Ticket []byte
}

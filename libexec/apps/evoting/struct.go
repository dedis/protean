package evoting

import (
	easyneff "github.com/dedis/protean/easyneff/base"
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

type EncBallots struct {
	Data protean.ElGamalPairs
}

type Ballot struct {
	Data protean.ElGamalPair
}

type VoteInput struct {
	Ballot Ballot
}

type VoteOutput struct {
	WS byzcoin.Arguments
}

type CloseInput struct {
	Barrier   int
	BlkHeight int
}

type CloseOutput struct {
	WS byzcoin.Arguments
}

type PrepShufOutput struct {
	Input easyneff.ShuffleInput
}

type PrepProofsInput struct {
	ShProofs easyneff.ShuffleOutput
}

type PrepProofsOutput struct {
	WS byzcoin.Arguments
}

type PrepDecOutput struct {
	Input threshold.DecryptInput
}

type TallyInput struct {
	CandCount int
	Ps        []kyber.Point
}

type TallyOutput struct {
	WS byzcoin.Arguments
}

type DecBallots struct {
	Data [][]byte
}

type ElectionResult struct {
	VoteCounts []int
}

//type FinalizeInput struct {
//	Ps []kyber.Point
//}
//
//type FinalizeOutput struct {
//	WS byzcoin.Arguments
//}
//
//type DecTickets struct {
//	Data [][]byte
//}
//
//type Winner struct {
//	Index  int
//	Ticket []byte
//}

package randlottery

import (
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

type JoinLotteryInput struct {
	Ticket Ticket
}

type JoinLotteryOutput struct {
	WS byzcoin.Arguments
}

//type JoinLotteryInput struct {
//	Ticket Ticket
//	KVData KVInputData
//}
//
//// Ticket is an input of JoinLottery
//type Ticket struct {
//	Key kyber.Point
//	Sig []byte
//}
//
//// KVInputData is an input of JoinLottery
//type KVInputData struct {
//	StateProof core.StateProof
//	Genesis    skipchain.SkipBlock
//}
//
//type CloseJoinInput struct {
//	KVData KVInputData
//	// needs to match the CONST value in the workflow
//	BlockNum int
//}
//
//type RevealWinnerInput struct {
//	KVData     KVInputData
//	Randomness RandomnessData
//	// needs to match the CONST value in the workflow
//	Round int
//}
//
//// RandomnessData is an input
//type RandomnessData struct {
//	Public kyber.Point
//	Round  uint64
//	Prev   []byte
//	// Value is the collective signature. Use the hash of it!
//	Value []byte
//}
//
//// KVOutputData is an output of JoinLottery
//type KVOutputData struct {
//	Args byzcoin.Arguments
//}
//

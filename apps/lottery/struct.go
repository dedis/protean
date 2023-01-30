package lottery

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
)

// KVInputData is an input of JoinLottery
type KVInputData struct {
	StateProof core.StateProof
	Genesis    skipchain.SkipBlock
}

// KVOutputData is an output of JoinLottery
type KVOutputData struct {
	Args byzcoin.Arguments
}

type JoinLotteryInput struct {
	Ticket Ticket
	KVData KVInputData
}

// Ticket is an input of JoinLottery
type Ticket struct {
	Key kyber.Point
	Sig []byte
}

type Tickets struct {
	Data []Ticket
}

type RevealWinnerInput struct {
	KVData     KVInputData
	Randomness RandomnessData
	Round      int
}

// RandomnessData is an input
type RandomnessData struct {
	Public kyber.Point
	Round  uint64
	Prev   []byte
	// Value is the collective signature. Use the hash of it!
	Value []byte
}

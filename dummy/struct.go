package dummy

import (
	"time"

	"github.com/dedis/protean"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
)

//type Storage struct {
//Data []KV
//}

//type LotteryStorage struct {
//Storage []KV
//}

type KV struct {
	Key   string
	Value []byte
}

type KVStorage struct {
	KV []KV
}

type LotteryValue struct {
	Data []byte
	Sig  []byte
}

type CalyLotteryStorage struct {
	//Key: public key of the participant
	//Value: proof + hash of ticket + sig
	WriteData KVStorage
	ReadData  [][]byte
	//FinalData CalyData
}

type WriteDataValue struct {
	Proof  *byzcoin.Proof
	Digest []byte
	Sig    []byte
}

type CalyLotteryValue struct {
	Data []byte
	Sig  []byte
}

type InitUnitRequest struct {
	Roster       *onet.Roster
	ScData       *protean.ScInitData
	BaseStore    *protean.BaseStorage
	BlkInterval  time.Duration
	DurationType time.Duration
}

type InitUnitReply struct {
	Genesis []byte
}

type CreateStateRequest struct {
	Ctx  byzcoin.ClientTransaction
	Wait int
}

type CreateStateReply struct {
	InstanceID byzcoin.InstanceID
}

type UpdateStateRequest struct {
	Ctx  byzcoin.ClientTransaction
	Wait int
}

type UpdateStateReply struct {
}

type SpawnDarcRequest struct {
	Darc darc.Darc
	Wait int
}

type SpawnDarcReply struct {
}

type GetProofRequest struct {
	InstanceID byzcoin.InstanceID
}

type GetProofReply struct {
	*byzcoin.GetProofResponse
}

type InitByzcoinRequest struct {
	Roster       *onet.Roster
	BlkInterval  time.Duration
	DurationType time.Duration
}

type InitByzcoinReply struct{}

type CopyRequest struct {
	Genesis skipchain.SkipBlockID
}

type CopyReply struct{}

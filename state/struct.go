package state

import (
	"time"

	"github.com/ceyhunalp/protean_code"
	"github.com/ceyhunalp/protean_code/utils"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
)

type KV struct {
	Key   string
	Value []byte
}

type Storage struct {
	//Data []*KV
	Data map[string][]byte
}

type InitUnitRequest struct {
	ScData       *utils.ScInitData
	UnitData     *protean.UnitStorage
	BlkInterval  time.Duration
	DurationType time.Duration
}

type InitUnitReply struct {
	Genesis []byte
	//Sb      *skipchain.SkipBlock
}

type CreateStateRequest struct {
	ExecData *protean.ExecutionData
	Ctx      byzcoin.ClientTransaction
	Wait     int
}

type CreateStateReply struct {
	//AddTxResp *byzcoin.AddTxResponse
	InstID [32]byte
	Sig    protocol.BlsSignature
}

type UpdateStateRequest struct {
	ExecData *protean.ExecutionData
	Ctx      byzcoin.ClientTransaction
	Wait     int
}

type UpdateStateReply struct {
	//AddTxResp *byzcoin.AddTxResponse
	Sig protocol.BlsSignature
}

type SpawnDarcRequest struct {
	//Ctx  byzcoin.ClientTransaction
	Darc darc.Darc
	Wait int
}

type SpawnDarcReply struct {
}

type GetProofRequest struct {
	InstID []byte
}

type GetProofReply struct {
	*byzcoin.GetProofResponse
}

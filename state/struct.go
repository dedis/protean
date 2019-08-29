package state

import (
	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
)

type KV struct {
	Key   string
	Value []byte
}

type Storage struct {
	//Data map[string][]byte
	Data []KV
}

type InitUnitRequest struct {
	//Roster *onet.Roster
	//ScData       *sys.ScInitData
	//BaseStore    *sys.BaseStorage
	//BlkInterval  time.Duration
	//DurationType time.Duration
	Cfg *sys.UnitConfig
}

type InitUnitReply struct {
	Genesis []byte
}

type CreateStateRequest struct {
	ExecData *sys.ExecutionData
	Ctx      byzcoin.ClientTransaction
	Wait     int
}

type CreateStateReply struct {
	InstanceID byzcoin.InstanceID
	Sig        protocol.BlsSignature
}

type UpdateStateRequest struct {
	//ExecData *protean.ExecutionData
	ExecData *sys.ExecutionData
	Ctx      byzcoin.ClientTransaction
	Wait     int
}

type UpdateStateReply struct {
	//AddTxResp *byzcoin.AddTxResponse
	Sig protocol.BlsSignature
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

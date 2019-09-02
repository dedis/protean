package state

import (
	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
)

const DARC = "SpawnDarc"
const CREAT = "CreateState"
const UPD = "UpdateState"
const PROOF = "GetProof"

type KV struct {
	Key   string
	Value []byte
}

type Storage struct {
	Data []KV
}

type InitUnitRequest struct {
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

type SpawnDarcReply struct{}

type GetProofRequest struct {
	InstanceID byzcoin.InstanceID
}

type GetProofReply struct {
	*byzcoin.GetProofResponse
}

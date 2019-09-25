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

type Keys struct {
	// Hex strings
	List []string
}

type KV struct {
	Key     string
	Value   []byte
	Version uint32
}

type InitUnitRequest struct {
	Cfg *sys.UnitConfig
}

type InitUnitReply struct {
	Genesis []byte
}

type SpawnDarcRequest struct {
	Darc     darc.Darc
	Wait     int
	ExecData *sys.ExecutionData
}

type SpawnDarcReply struct {
	Sig protocol.BlsSignature
}

type CreateStateRequest struct {
	Ctx      byzcoin.ClientTransaction
	Wait     int
	ExecData *sys.ExecutionData
}

type CreateStateReply struct {
	InstanceID byzcoin.InstanceID
	Sig        protocol.BlsSignature
}

type UpdateStateRequest struct {
	Ctx      byzcoin.ClientTransaction
	Wait     int
	ExecData *sys.ExecutionData
}

type UpdateStateReply struct {
	Sig protocol.BlsSignature
}

type GetProofRequest struct {
	InstanceID byzcoin.InstanceID
	ExecData   *sys.ExecutionData
}

type GetProofReply struct {
	*byzcoin.GetProofResponse
	Sig protocol.BlsSignature
}

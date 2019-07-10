package state

import (
	"github.com/ceyhunalp/protean_code/compiler"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
)

//type unitStorage struct {
//UnitID   string
//Txns     map[string]string
//CompKeys []kyber.Point
//}

type KeyValue struct {
	Key   string
	Value []byte
}

type KVData struct {
	Storage []*KeyValue
	//Storage map[string]*KeyValue
}

type SetKVRequest struct {
	// Protean-related stuff
	Index    int
	ExecPlan *compiler.ExecutionPlan
	SigMap   map[int]protocol.BlsSignature
}

type SetKVReply struct {
	*byzcoin.AddTxResponse
	byzcoin.InstanceID
}

type UpdateStateRequest struct {
	Index    int
	ExecPlan *compiler.ExecutionPlan
	PlanSig  protocol.BlsSignature
	SigMap   map[int]protocol.BlsSignature
}

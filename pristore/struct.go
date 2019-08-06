package pristore

import (
	"time"

	protean "github.com/dedis/protean"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

//type KV struct {
//Key   string
//Value []byte
//}

//type KVStorage struct {
//KV []KV
//}

type WriteData struct {
	ltsID     byzcoin.InstanceID
	writeDarc darc.ID
	aggKey    kyber.Point
	data      []byte
}

type InitUnitRequest struct {
	ScData       *protean.ScInitData
	BaseStore    *protean.BaseStorage
	BlkInterval  time.Duration
	DurationType time.Duration
}

type InitUnitReply struct {
	Genesis []byte
	ID      skipchain.SkipBlockID
}

type AuthorizeRequest struct {
	Request *calypso.Authorise
}

type AuthorizeReply struct {
	Reply *calypso.AuthoriseReply
}

type CreateLTSRequest struct {
	LTSRoster *onet.Roster
	Wait      int
}

type CreateLTSReply struct {
	Reply *calypso.CreateLTSReply
}

type SpawnDarcRequest struct {
	Darc darc.Darc
	Wait int
}

type SpawnDarcReply struct {
}

type AddWriteRequest struct {
	//ExecData *protean.ExecutionData
	Ctx  byzcoin.ClientTransaction
	Wait int
}

type AddWriteReply struct {
	InstanceID byzcoin.InstanceID
}

type AddReadRequest struct {
	//ExecData *protean.ExecutionData
	Ctx  byzcoin.ClientTransaction
	Wait int
}

type AddReadReply struct {
	InstanceID byzcoin.InstanceID
}

type DecryptRequest struct {
	//ExecData *protean.ExecutionData
	Request *calypso.DecryptKey
}

type DecryptReply struct {
	Reply *calypso.DecryptKeyReply
}

type GetProofRequest struct {
	InstanceID byzcoin.InstanceID
}

type GetProofReply struct {
	*byzcoin.GetProofResponse
}

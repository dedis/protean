package pristore

import (
	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

const DARC = "SpawnDarc"
const LTS = "CreateLTS"
const WRITE = "AddWrite"
const READ = "AddRead"
const READBATCH = "AddReadBatch"
const PROOF = "GetProof"
const PROOFBATCH = "GetProofBatch"
const DEC = "Decrypt"
const DECBATCH = "DecryptBatch"
const DECNT = "DecryptNT"
const DECNTBATCH = "DecryptNTBatch"

type IID struct {
	Valid bool
	ID    byzcoin.InstanceID
}

type GPR struct {
	Valid bool
	Resp  *byzcoin.GetProofResponse
}

type WriteData struct {
	ltsID     byzcoin.InstanceID
	writeDarc darc.ID
	aggKey    kyber.Point
	data      []byte
}

type InitUnitRequest struct {
	Cfg *sys.UnitConfig
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
	ExecData  *sys.ExecutionData
}

type CreateLTSReply struct {
	Reply *calypso.CreateLTSReply
	Sig   protocol.BlsSignature
}

type SpawnDarcRequest struct {
	Darc     darc.Darc
	Wait     int
	ExecData *sys.ExecutionData
}

type SpawnDarcReply struct {
	Sig protocol.BlsSignature
}

type AddWriteRequest struct {
	Ctx      byzcoin.ClientTransaction
	Wait     int
	ExecData *sys.ExecutionData
}

type AddWriteReply struct {
	InstanceID byzcoin.InstanceID
	Sig        protocol.BlsSignature
}

type AddReadRequest struct {
	Ctx      byzcoin.ClientTransaction
	Wait     int
	ExecData *sys.ExecutionData
}

type AddReadReply struct {
	InstanceID byzcoin.InstanceID
	Sig        protocol.BlsSignature
}

type AddReadBatchRequest struct {
	Ctxs     []byzcoin.ClientTransaction
	Wait     int
	ExecData *sys.ExecutionData
}

type AddReadBatchReply struct {
	IIDBatch []*IID
	Sig      protocol.BlsSignature
}

type GetProofRequest struct {
	InstanceID byzcoin.InstanceID
	ExecData   *sys.ExecutionData
}

type GetProofReply struct {
	ProofResp *byzcoin.GetProofResponse
	Sig       protocol.BlsSignature
}

type GetProofBatchRequest struct {
	IIDBatch []*IID
	ExecData *sys.ExecutionData
}

type GetProofBatchReply struct {
	PrBatch []*GPR
	Sig     protocol.BlsSignature
}

type DecryptRequest struct {
	Request  *calypso.DecryptKey
	ExecData *sys.ExecutionData
}

type DecryptReply struct {
	CalyReply *calypso.DecryptKeyReply
	Sig       protocol.BlsSignature
}

type DecryptNTRequest struct {
	Request  *calypso.DecryptKeyNT
	ExecData *sys.ExecutionData
}

type DecryptNTReply struct {
	CalyReply *calypso.DecryptKeyNTReply
	Sig       protocol.BlsSignature
}

// Batch requests

type DecryptBatchRequest struct {
	Requests []*calypso.DecryptKey
	ExecData *sys.ExecutionData
}

type DecryptBatchReply struct {
	CalyReplies []*calypso.DecryptKeyReply
	Sig         protocol.BlsSignature
}

////

type signReencData struct {
	ID      string
	XhatEnc kyber.Point
}

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
const PROOF = "GetProof"
const DEC = "Decrypt"

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
}

type CreateLTSReply struct {
	Reply *calypso.CreateLTSReply
}

type SpawnDarcRequest struct {
	ExecData *sys.ExecutionData
	Darc     darc.Darc
	Wait     int
}

type SpawnDarcReply struct {
	Sig protocol.BlsSignature
}

type AddWriteRequest struct {
	ExecData *sys.ExecutionData
	Ctx      byzcoin.ClientTransaction
	Wait     int
}

type AddWriteReply struct {
	InstanceID byzcoin.InstanceID
	Sig        protocol.BlsSignature
}

type AddReadRequest struct {
	ExecData *sys.ExecutionData
	Ctx      byzcoin.ClientTransaction
	Wait     int
}

type AddReadReply struct {
	InstanceID byzcoin.InstanceID
	Sig        protocol.BlsSignature
}

type DecryptRequest struct {
	ExecData *sys.ExecutionData
	Request  *calypso.DecryptKey
}

type DecryptReply struct {
	Reply *calypso.DecryptKeyReply
	Sig   protocol.BlsSignature
}

type GetProofRequest struct {
	ExecData   *sys.ExecutionData
	InstanceID byzcoin.InstanceID
}

type GetProofReply struct {
	*byzcoin.GetProofResponse
	Sig protocol.BlsSignature
}

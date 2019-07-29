package dummy

import (
	"time"

	protean "github.com/ceyhunalp/protean_code"
	"github.com/ceyhunalp/protean_code/utils"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3"
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
	ScData       *utils.ScInitData
	BaseStore    *protean.BaseStorage
	BlkInterval  time.Duration
	DurationType time.Duration
}

type InitUnitReply struct {
	Genesis []byte
	//Sb      *skipchain.SkipBlock
}

type CreateStateRequest struct {
	Ctx  byzcoin.ClientTransaction
	Wait int
}

type CreateStateReply struct {
	InstID byzcoin.InstanceID
}

type UpdateStateRequest struct {
	Ctx  byzcoin.ClientTransaction
	Wait int
}

type UpdateStateReply struct {
	//AddTxResp *byzcoin.AddTxResponse
	//InstID    [32]byte
	//InstID    byzcoin.InstanceID
	//Sig protocol.BlsSignature
}

type SpawnDarcRequest struct {
	Darc darc.Darc
	Wait int
}

type SpawnDarcReply struct {
}

type GetProofRequest struct {
	InstID byzcoin.InstanceID
	//InstID []byte
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

//type ByzData struct {
//Darc      darc.Darc
//Signer    darc.Signer
//Wait      int
//SignerCtr uint64
//}

package dummy

import (
	"time"

	protean "github.com/ceyhunalp/protean_code"
	"github.com/ceyhunalp/protean_code/utils"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
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
	InstanceID byzcoin.InstanceID
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
	InstanceID byzcoin.InstanceID
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

package easyneff

import (
	"time"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

type InitUnitRequest struct {
	Roster *onet.Roster
	//ScData       *protean.ScInitData
	//BaseStore    *protean.BaseStorage
	ScData       *sys.ScInitData
	BaseStore    *sys.BaseStorage
	BlkInterval  time.Duration
	DurationType time.Duration
}

type InitUnitReply struct {
	Genesis []byte
}

// ShuffleRequest is a message that the client sends to initiate Neff shuffle. The
// points G and H are public generators used in ElGamal encryption.
type ShuffleRequest struct {
	//Pairs []ElGamalPair
	Pairs []utils.ElGamalPair
	G, H  kyber.Point
	//Roster *onet.Roster
}

// Response is the result of all the proofs of the shuffle. The client is
// responsible for verifying the result.
//type Response struct {
type ShuffleReply struct {
	Proofs []Proof
}

// ElGamalPair is an ElGamal ciphertext.
//type ElGamalPair struct {
//C1 kyber.Point
//C2 kyber.Point
//}

// Proof is the Neff shuffle proof with a signature.
type Proof struct {
	//Pairs     []ElGamalPair
	Pairs     []utils.ElGamalPair
	Proof     []byte
	Signature []byte // on the Proof
}

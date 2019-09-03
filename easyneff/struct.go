package easyneff

import (
	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
)

const SH = "Shuffle"

type InitUnitRequest struct {
	Cfg *sys.UnitConfig
}

type InitUnitReply struct {
	Genesis []byte
}

// ShuffleRequest is a message that the client sends to initiate Neff shuffle. The
// points G and H are public generators used in ElGamal encryption.
type ShuffleRequest struct {
	Pairs    []utils.ElGamalPair
	G        kyber.Point
	H        kyber.Point
	ExecData *sys.ExecutionData
}

// Response is the result of all the proofs of the shuffle. The client is
// responsible for verifying the result.
//type Response struct {
type ShuffleReply struct {
	Proofs []Proof
	Sig    protocol.BlsSignature
}

// Proof is the Neff shuffle proof with a signature.
type Proof struct {
	Pairs     []utils.ElGamalPair
	Proof     []byte
	Signature []byte // on the Proof
}

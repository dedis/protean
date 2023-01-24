package threshold

import (
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

const DKG = "InitDKG"
const DEC = "Decrypt"

type DKGID [32]byte

type InitUnitRequest struct {
	Roster *onet.Roster
}

type InitUnitReply struct{}

type InitDKGRequest struct {
	ID DKGID
	//ExecData *sys.ExecutionData
}

type InitDKGReply struct {
	X   kyber.Point
	Sig protocol.BlsSignature
}

type DecryptRequest struct {
	ID DKGID
	Cs []utils.ElGamalPair
	//ExecData *sys.ExecutionData
}

type DecryptReply struct {
	Ps        []kyber.Point
	Signature protocol.BlsSignature
}

// Internal structs

type pubPoly struct {
	B       kyber.Point
	Commits []kyber.Point
}

//type DecryptReply struct {
//	// If server = true, Ps will contain the plaintext. If server =
//	// false, Ps will be nil
//	Ps []kyber.Point
//	// If server = false, partials will contain the partial decryptions and
//	// decryption proofs. If server = true, partials will be nil
//	partials  []*Partial
//	Signature protocol.BlsSignature
//}

package easyneff

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyneff/protocol"
	"github.com/dedis/protean/utils"
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"golang.org/x/xerrors"
)

const SH = "Shuffle"

type InitUnitRequest struct {
	Roster *onet.Roster
}

type InitUnitReply struct{}

// ShuffleRequest is a message that the client sends to initiate Neff shuffle. The
// points G and H are public generators used in ElGamal encryption.
type ShuffleRequest struct {
	Pairs []utils.ElGamalPair
	H     kyber.Point
	//ExecData *sys.ExecutionData
}

// ShuffleReply is the result of all the proofs of the shuffle. The client is
// responsible for verifying the result.
type ShuffleReply struct {
	Proofs    []protocol.Proof
	Signature blscosi.BlsSignature
}

func (r *ShuffleRequest) getOpcodeHashes(ep *core.ExecutionPlan,
	idx int) (map[string][]byte, error) {
	opcodeHashes := make(map[string][]byte)
	deps := ep.Txn.Opcodes[idx].Dependencies
	for inputName, dep := range deps {
		if dep.Src == core.OPCODE {
			if inputName == "pairs" {
				hash, err := utils.Pairs(r.Pairs).Hash()
				if err != nil {
					return nil, err
				}
				opcodeHashes[inputName] = hash
			} else {
				return nil, xerrors.Errorf("invalid input name: %s", inputName)
			}
		}
	}
	return opcodeHashes, nil
}

//func getPointHash(p kyber.Point) ([]byte, error) {
//	buf, err := p.MarshalBinary()
//	if err != nil {
//		return nil, xerrors.Errorf("cannot compute hash of point: %v", err)
//	}
//	h := sha256.New()
//	h.Write(buf)
//	return h.Sum(nil), nil
//}

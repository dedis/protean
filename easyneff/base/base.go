package base

import (
	"github.com/dedis/protean/utils"
	"go.dedis.ch/kyber/v3"
)

const (
	UID     string = "easyneff"
	SHUFFLE string = "shuffle"
)

type ShuffleInput struct {
	Pairs utils.ElGamalPairs
	H     kyber.Point
}

func (shInput *ShuffleInput) prepareInputHashes() (map[string][]byte, error) {
	inputHashes := make(map[string][]byte)
	hash, err := shInput.Pairs.Hash()
	if err != nil {
		return nil, err
	}
	inputHashes["pairs"] = hash
	hash, err = utils.Hash(shInput.H)
	if err != nil {
		return nil, err
	}
	inputHashes["h"] = hash
	return inputHashes, nil
}

//func (r *ShuffleRequest) getOpcodeHashes(ep *core.ExecutionPlan,
//	idx int) (map[string][]byte, error) {
//	opcodeHashes := make(map[string][]byte)
//	deps := ep.Txn.Opcodes[idx].Dependencies
//	for inputName, dep := range deps {
//		if dep.Src == core.OPCODE {
//			if inputName == "pairs" {
//				hash, err := utils.Pairs(r.Pairs).Hash()
//				if err != nil {
//					return nil, err
//				}
//				opcodeHashes[inputName] = hash
//			} else {
//				return nil, xerrors.Errorf("invalid input name: %s", inputName)
//			}
//		}
//	}
//	return opcodeHashes, nil
//}

//func getPointHash(p kyber.Point) ([]byte, error) {
//	buf, err := p.MarshalBinary()
//	if err != nil {
//		return nil, xerrors.Errorf("cannot compute hash of point: %v", err)
//	}
//	h := sha256.New()
//	h.Write(buf)
//	return h.Sum(nil), nil
//}

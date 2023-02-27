package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/dedis/protean/core"
	"golang.org/x/xerrors"
	"strconv"

	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

func prepareExecutionPlan(data *sbData, wf *sys.Workflow) (*sys.ExecutionPlan, error) {
	publics := make(map[string]*sys.UnitIdentity)
	for _, wfn := range wf.Nodes {
		if uv, ok := data.Data[wfn.UID]; ok {
			publics[wfn.UID] = &sys.UnitIdentity{Keys: uv.Ps}
		} else {
			return nil, fmt.Errorf("Functional unit does not exist")
		}
	}
	return &sys.ExecutionPlan{Workflow: wf, UnitPublics: publics}, nil
}

func VerifyDag(contract *core.Contract) error {
	for wfName, wf := range contract.Workflows {
		for txnName, txn := range wf.Txns {
			var edges []*edge
			nodes := make(map[int]bool)
			for idx, opcode := range txn.Opcodes {
				nodes[idx] = true
				for _, dep := range opcode.Dependencies {
					if dep.Src == core.OPCODE {
						edges = append(edges, &edge{parent: dep.Idx,
							child: idx, removed: false})
					}
				}
			}
			var sorted []int
			idx := 0
			noIncoming := findNoIncoming(nodes, edges)
			for idx < len(noIncoming) {
				curr := noIncoming[idx]
				sorted = append(sorted, curr)
				for i := 0; i < len(edges); i++ {
					tmp := edges[i]
					if curr == tmp.parent && tmp.removed == false {
						tmp.removed = true
						if !hasIncomingEdge(tmp.child, edges) {
							noIncoming = append(noIncoming, tmp.child)
						}
					}
				}
				idx++
			}
			for _, edge := range edges {
				if edge.removed == false {
					return xerrors.Errorf("%s:%s has circular dependency",
						wfName, txnName)
				}
			}
		}
	}
	return nil
}

//
//func verifyDag(wfNodes []*sys.WfNode) error {
//	var edges []*edge
//	//levels := make(map[int]int)
//	nodes := make(map[int]bool)
//	for idx, wfn := range wfNodes {
//		//levels[idx] = -1
//		nodes[idx] = true
//		for _, p := range wfn.Deps {
//			edges = append(edges, &edge{parent: p, child: idx, removed: false})
//		}
//	}
//	var sorted []int
//	idx := 0
//	//noIncoming := findNoIncoming(nodes, edges, levels)
//	noIncoming := findNoIncoming(nodes, edges)
//	for idx < len(noIncoming) {
//		curr := noIncoming[idx]
//		sorted = append(sorted, curr)
//		for i := 0; i < len(edges); i++ {
//			tmp := edges[i]
//			if curr == tmp.parent && tmp.removed == false {
//				tmp.removed = true
//				if !hasIncomingEdge(tmp.child, edges) {
//					noIncoming = append(noIncoming, tmp.child)
//				}
//				//currLvl := levels[tmp.child]
//				//newLvl := levels[curr] + 1
//				//if currLvl != -1 {
//				//levels[tmp.child] = newLvl
//				//} else {
//				//if newLvl > currLvl {
//				//levels[tmp.child] = newLvl
//				//}
//				//}
//			}
//		}
//		idx++
//	}
//	for _, edge := range edges {
//		if edge.removed == false {
//			return fmt.Errorf("Workflow has a circular dependency")
//		}
//	}
//	return nil
//}

func hasIncomingEdge(node int, edges []*edge) bool {
	for _, edge := range edges {
		if (node == edge.child) && (edge.removed == false) {
			return true
		}
	}
	return false
}

func findNoIncoming(nodes map[int]bool, edges []*edge) []int {
	var noIncoming []int
	for _, edge := range edges {
		nodes[edge.child] = false
	}
	for k, v := range nodes {
		if v == true {
			noIncoming = append(noIncoming, k)
		}
	}
	return noIncoming
}

func getBlockData(db *skipchain.SkipBlockDB, genesis []byte) (*sbData, error) {
	latest, err := db.GetLatest(db.GetByID(genesis))
	if err != nil {
		return nil, err
	}
	data := &sbData{}
	err = protobuf.DecodeWithConstructors(latest.Data, data, network.DefaultConstructors(cothority.Suite))
	return data, err

}

func generateUnitID(fu *sys.FunctionalUnit) (string, error) {
	rid, err := fu.Roster.GetID()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(rid.String()))
	h.Write([]byte(strconv.Itoa(fu.Type)))
	h.Write([]byte(fu.Name))
	for _, t := range fu.Txns {
		h.Write([]byte(t))
	}
	tmp := h.Sum(nil)
	return hex.EncodeToString(tmp), nil
}

func generateTxnMap(tList []string) map[string]string {
	txns := make(map[string]string)
	for _, txnName := range tList {
		tmp := sha256.Sum256([]byte(txnName))
		txns[hex.EncodeToString(tmp[:])] = txnName
	}
	return txns
}

//func (req ExecutionPlanRequest) Hash() []byte {
//h := sha256.New()
//for _, wfn := range req.Workflow.Nodes {
//h.Write([]byte(wfn.UID))
//h.Write([]byte(wfn.TID))
//}
//return h.Sum(nil)
//}

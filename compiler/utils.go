package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

//func prepareExecutionPlan(data *sbData, req *ExecutionPlanRequest) (*protean.ExecutionPlan, error) {
func prepareExecutionPlan(data *sbData, req *ExecutionPlanRequest) (*sys.ExecutionPlan, error) {
	//publics := make(map[string]*protean.Identity)
	publics := make(map[string]*sys.Identity)
	for _, wfn := range req.Workflow {
		log.Info("workflow node:", wfn.UID, wfn.TID)
		if uv, ok := data.Data[wfn.UID]; ok {
			if _, ok := publics[wfn.UID]; !ok {
				//publics[wfn.UID] = &protean.Identity{Keys: uv.Ps}
				publics[wfn.UID] = &sys.Identity{Keys: uv.Ps}
			}
		} else {
			return nil, fmt.Errorf("Functional unit does not exist")
		}
	}
	//return &protean.ExecutionPlan{Workflow: req.Workflow, Publics: publics}, nil
	return &sys.ExecutionPlan{Workflow: req.Workflow, Publics: publics}, nil
}

//func verifyDag(wf []*protean.WfNode) bool {
func verifyDag(wf []*sys.WfNode) bool {
	var edges []*edge
	nodes := make(map[int]bool)
	for idx, wfn := range wf {
		nodes[idx] = true
		for _, p := range wfn.Deps {
			edges = append(edges, &edge{parent: p, child: idx, removed: false})
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
			log.Errorf("Error: Graph has a cycle")
			return false
		}
	}
	log.Info("TOPOLOGICAL SORT:", sorted)
	return true
}

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
		//log.Errorf("Cannot get the latest block: %v", err)
		return nil, err
	}
	data := &sbData{}
	err = protobuf.DecodeWithConstructors(latest.Data, data, network.DefaultConstructors(cothority.Suite))
	//if err != nil {
	//log.Errorf("Protobuf error decoding with constructors: %v", err)
	//return nil, err
	//}
	//return data, nil
	return data, err

}

func (req ExecutionPlanRequest) Hash() []byte {
	h := sha256.New()
	for _, wfn := range req.Workflow {
		h.Write([]byte(wfn.UID))
		h.Write([]byte(wfn.TID))
	}
	return h.Sum(nil)
}

func generateUnitID(fu *sys.FunctionalUnit) string {
	h := sha256.New()
	h.Write([]byte(strconv.Itoa(fu.Type)))
	h.Write([]byte(fu.Roster.ID.String()))
	h.Write([]byte(fu.Name))
	for _, t := range fu.Txns {
		h.Write([]byte(t))
	}
	tmp := h.Sum(nil)
	return hex.EncodeToString(tmp)
}

func generateTxnMap(tList []string) map[string]string {
	txns := make(map[string]string)
	for _, txnName := range tList {
		tmp := sha256.Sum256([]byte(txnName))
		txns[hex.EncodeToString(tmp[:])] = txnName
	}
	return txns
}

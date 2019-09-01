package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

func prepareExecutionPlan(data *sbData, req *ExecutionPlanRequest) (*sys.ExecutionPlan, error) {
	err := verifyAuthentication(req.Workflow, req.SigMap)
	if err != nil {
		return nil, err
	}
	publics := make(map[string]*sys.UnitIdentity)
	for _, wfn := range req.Workflow.Nodes {
		if uv, ok := data.Data[wfn.UID]; ok {
			publics[wfn.UID] = &sys.UnitIdentity{Keys: uv.Ps}
		} else {
			return nil, fmt.Errorf("Functional unit does not exist")
		}
	}
	return &sys.ExecutionPlan{Workflow: req.Workflow, Publics: publics}, nil
}

func verifyAuthentication(wf *sys.Workflow, sigMap map[string][]byte) error {
	if len(sigMap) == 0 {
		log.LLvlf1("Workflow does not have authorized users")
		return nil
	}
	//msg, err := protobuf.Encode(wf)
	//if err != nil {
	//return err
	//}
	digest, err := utils.ComputeWFHash(wf)
	if err != nil {
		return err
	}
	if wf.All {
		for id, authPub := range wf.AuthPublics {
			sig, ok := sigMap[id]
			if !ok {
				return fmt.Errorf("Missing signature from %v", id)
			}
			//err := schnorr.Verify(cothority.Suite, authPub, msg, sig)
			err := schnorr.Verify(cothority.Suite, authPub, digest, sig)
			if err != nil {
				return fmt.Errorf("Cannot verify signature from %v", id)
			}
		}
	} else {
		success := false
		for id, sig := range sigMap {
			pk, ok := wf.AuthPublics[id]
			if !ok {
				return fmt.Errorf("Cannot find %v in authenticated users", id)
			}
			//err := schnorr.Verify(cothority.Suite, pk, msg, sig)
			err := schnorr.Verify(cothority.Suite, pk, digest, sig)
			if err == nil {
				success = true
				break
			}
		}
		if !success {
			return fmt.Errorf("Cannot verify a signature against the given authenticated users")
		}
	}
	return nil
}

func verifyDag(wfNodes []*sys.WfNode) error {
	var edges []*edge
	nodes := make(map[int]bool)
	for idx, wfn := range wfNodes {
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
			return fmt.Errorf("Workflow has a circular dependency")
		}
	}
	//log.Info("TOPOLOGICAL SORT:", sorted)
	return nil
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
		return nil, err
	}
	data := &sbData{}
	err = protobuf.DecodeWithConstructors(latest.Data, data, network.DefaultConstructors(cothority.Suite))
	return data, err

}

func (req ExecutionPlanRequest) Hash() []byte {
	h := sha256.New()
	for _, wfn := range req.Workflow.Nodes {
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

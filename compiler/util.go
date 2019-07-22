package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/ceyhunalp/protean_code"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

func prepareExecutionPlan(data *sbData, req *ExecutionPlanRequest) (*protean.ExecutionPlan, error) {
	//publics := make(map[string][]kyber.Point)
	publics := make(map[string]*protean.Identity)
	for _, wfn := range req.Workflow {
		log.Info("workflow node:", wfn.UID, wfn.TID)
		if uv, ok := data.Data[wfn.UID]; ok {
			if _, ok := publics[wfn.UID]; !ok {
				//publics[wfn.UID] = uv.Ps
				publics[wfn.UID] = &protean.Identity{Keys: uv.Ps}
			}
		} else {
			log.Errorf("[prepareExecutionPlan] Functional unit does not exist")
			return nil, fmt.Errorf("[prepareExecutionPlan] Functional unit does not exist")
		}
	}
	//TODO: Revert to EP w/o genesis
	//return &ExecutionPlan{Workflow: req.Workflow, Publics: publics}, nil
	return &protean.ExecutionPlan{Genesis: req.Genesis, Workflow: req.Workflow, Publics: publics}, nil
}

func verifyDag(wf []*protean.WfNode) bool {
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
			log.Errorf("[verifyDag] Error: Graph has a cycle")
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
		log.Errorf("[getBlockData] Could not get the latest block: %v", err)
		return nil, err
	}
	data := &sbData{}
	err = protobuf.DecodeWithConstructors(latest.Data, data, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		log.Errorf("[getBlockData] Protobuf error decoding with constructors: %v", err)
		return nil, err
	}
	return data, nil

}

func (req ExecutionPlanRequest) Hash() []byte {
	h := sha256.New()
	for _, wfn := range req.Workflow {
		h.Write([]byte(wfn.UID))
		h.Write([]byte(wfn.TID))
	}
	return h.Sum(nil)
}

func joinStrings(strs ...string) (string, error) {
	var sb strings.Builder
	for _, str := range strs {
		_, err := sb.WriteString(str)
		if err != nil {
			log.Errorf("[joinStrings] %v", err)
			return "", err
		}
	}
	return sb.String(), nil
}

func generateUnitID(fu *FunctionalUnit) (string, error) {
	var uid string
	typeStr := strconv.Itoa(fu.UnitType)
	uuidStr := fu.Roster.ID.String()
	log.Info("UUID STR IS:", uuidStr)
	uidStr, err := joinStrings(typeStr, fu.UnitName, uuidStr)
	if err != nil {
		log.Errorf("[generateUnitID] Error while generating the unit key: %v", err)
		return uid, err
	}
	tmp := sha256.Sum256([]byte(uidStr))
	return hex.EncodeToString(tmp[:]), nil
}

func generateTxnIDs(tList []string) map[string]string {
	txns := make(map[string]string)
	for _, txnName := range tList {
		tmp := sha256.Sum256([]byte(txnName))
		txns[hex.EncodeToString(tmp[:])] = txnName
	}
	return txns
}

//func checkUnitKeys(db *bolt.DB, bucketName []byte, unitIDs ...string) error {
//err := db.View(func(tx *bolt.Tx) error {
//for _, id := range unitIDs {
//log.LLvl3("Hex key is", id)
//key, err := hex.DecodeString(id)
//if err != nil {
//log.Errorf("checkUnitKeys error:%v", err)
//return err
//}
//log.LLvl3("Checking key(byte):", key)
//val := tx.Bucket(bucketName).Get(key)
//if val == nil {
//return fmt.Errorf("Unit key does not exist")
//}
//}
//return nil
//})
//return err
//}

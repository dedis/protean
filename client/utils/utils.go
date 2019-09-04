package utils

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3/log"
)

func PrepareWorkflow(wFilePtr *string, dirInfo map[string]*sys.UnitInfo, publics []kyber.Point, all bool) (*sys.Workflow, error) {
	var tmpWf []sys.WfJSON
	fh, err := os.Open(*wFilePtr)
	if err != nil {
		log.Errorf("Cannot open file %s: %v", *wFilePtr, err)
		return nil, err
	}
	defer fh.Close()
	buf, err := ioutil.ReadAll(fh)
	if err != nil {
		log.Errorf("Error reading file %s: %v", *wFilePtr, err)
		return nil, err
	}
	err = json.Unmarshal(buf, &tmpWf)
	if err != nil {
		log.Errorf("Cannot unmarshal json value: %v", err)
		return nil, err
	}
	sz := len(tmpWf)
	wfNodes := make([]*sys.WfNode, sz)
	for i := 0; i < sz; i++ {
		tmp := tmpWf[i]
		unitInfo, ok := dirInfo[tmp.UnitName]
		if ok {
			wfNodes[i] = &sys.WfNode{
				UID:  unitInfo.UnitID,
				TID:  unitInfo.Txns[tmp.TxnName],
				Deps: tmp.Deps,
			}
		}
	}

	var authPublics map[string]kyber.Point
	if publics != nil {
		authPublics = make(map[string]kyber.Point)
		for _, pk := range publics {
			authPublics[pk.String()] = pk
		}
	}
	return &sys.Workflow{Nodes: wfNodes, AuthPublics: authPublics, All: all}, nil
}

// TODO: For now we only ask the clients to sign the execution plan. However,
// note that the fields of an execution plan do not change over the course of
// its execution. In the case of requiring signatures from all authorized users
// to execute a workflow, it might be a good idea to produce a signature for
// each call that corresponds to a txn in the workflow. One option is to
// Sign(Index || EP) instead of Sign(EP).
func SignExecutionPlan(ep *sys.ExecutionPlan, sk kyber.Scalar) ([]byte, error) {
	epHash, err := utils.ComputeEPHash(ep)
	if err != nil {
		log.Errorf("Cannot compute the hash of the execution plan: %v", err)
		return nil, err
	}
	sig, err := schnorr.Sign(cothority.Suite, sk, epHash)
	if err != nil {
		log.Errorf("Cannot sign the workflow: %v", err)
	}
	return sig, err
}

package verify

import (
	"strings"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

func getBaseStorage(blk *skipchain.SkipBlock) (*sys.BaseStorage, error) {
	data := &sys.BaseStorage{}
	err := protobuf.DecodeWithConstructors(blk.Data, data, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		log.Errorf("Protobuf decode failed: %v", err)
		return nil, err
	}
	return data, nil
}

func verifyPlan(v *Verify) bool {
	storageData, err := getBaseStorage(v.Block)
	if err != nil {
		return false
	}
	// STEP 1: Check that the workflow node that represents this transaction
	// has the correct UID and TID.
	myWfNode := v.ExecPlan.Workflow.Nodes[v.Index]
	if strings.Compare(storageData.UnitID, myWfNode.UID) != 0 {
		log.Errorf("Invalid UID. Expected %s but received %s", storageData.UnitID, myWfNode.UID)
		return false
	}
	//This check ensures that the TID in the workflow corresponds to one of
	//the txns that is supported by our unit.
	txnName, ok := storageData.Txns[myWfNode.TID]
	if !ok {
		log.Errorf("Invalid TID: %s", myWfNode.TID)
		return false
	}
	// STEP 2: Check that the client made the correct function call
	if strings.Compare(txnName, v.TxnName) != 0 {
		log.Errorf("TID %s corresponds to %s, not %s", myWfNode.TID, txnName, v.TxnName)
		return false
	}
	// STEP 3: Check compiler unit's signature on the execution plan
	wf := v.ExecPlan.Workflow
	epHash, err := utils.ComputeEPHash(v.ExecPlan)
	if err != nil {
		log.Errorf("Error computing the execution plan hash: %v", err)
		return false
	}
	err = v.CompilerSig.Verify(suite, epHash, storageData.CompPublics)
	if err != nil {
		log.Errorf("Cannot verify blscosi signature on the execution plan: %v", err)
		return false
	}
	// STEP 4: Verify client signatures
	wfHash, err := utils.ComputeWFHash(wf)
	if err != nil {
		log.Errorf("Error computing the workflow hash: %v", err)
		return false
	}
	err = sys.VerifyAuthentication(wfHash, wf, v.ClientSigs)
	if err != nil {
		log.Errorf("Cannot verify that the request comes from an authorized user: %v", err)
		return false
	}
	//STEP 5: Check the dependencies
	for _, depIdx := range myWfNode.Deps {
		depUID := wf.Nodes[depIdx].UID
		sig := v.UnitSigs[depIdx]
		err = sig.Verify(suite, epHash, v.ExecPlan.Publics[depUID].Keys)
		if err != nil {
			log.Errorf("Cannot verify the signature of UID %s: %v", depUID, err)
			return false
		}
	}
	return true
}

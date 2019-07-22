package verify

/*
Struct holds the messages that will be sent around in the protocol. You have
to define each message twice: once the actual message, and a second time
with the `*onet.TreeNode` embedded. The latter is used in the handler-function
so that it can find out who sent the message.
*/
import (
	"crypto/sha256"
	"github.com/ceyhunalp/protean_code"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
	"strings"
)

// Name can be used from other packages to refer to this protocol.
const Name = "VerifyExecutionPlan"

var suite = pairing.NewSuiteBn256()

//type VerifyExecPlan func(vs *Verify) bool

type Verify struct {
	Index   int
	Plan    *protean.ExecutionPlan
	Block   *skipchain.SkipBlock
	PlanSig protocol.BlsSignature
	SigMap  map[int]protocol.BlsSignature
}

type ProtoVerify struct {
	*onet.TreeNode
	Verify
}

type VerifyReply struct {
	Success bool
}

type ProtoVerifyReply struct {
	*onet.TreeNode
	VerifyReply
}

func getStorageData(blk *skipchain.SkipBlock) (*protean.UnitStorage, error) {
	data := &protean.UnitStorage{}
	err := protobuf.DecodeWithConstructors(blk.Data, data, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		log.Errorf("protobuf decode failed: %v", err)
		return nil, err
	}
	return data, nil
}

func verifyPlan(v *Verify) bool {
	storageData, err := getStorageData(v.Block)
	if err != nil {
		return false
	}
	payload, err := protobuf.Encode(v.Plan)
	if err != nil {
		log.Errorf("protobuf decode fail: %v", err)
		return false
	}
	h := sha256.New()
	h.Write(payload)
	//STEP 1:
	//Check the signature from the compiler unit on the execution plan
	err = v.PlanSig.Verify(suite, payload, storageData.CompKeys)
	if err != nil {
		log.Errorf("Cannot verify blscosi signature on the execution plan: %v", err)
		return false
	}

	//STEP 2: Check that I'm the right guy to do the next thing
	//First find myself in the execution plan
	myWfNode := v.Plan.Workflow[v.Index]
	if strings.Compare(storageData.UnitID, myWfNode.UID) != 0 {
		log.Errorf("Invalid UID. Expected %s but received %s", storageData.UnitID, myWfNode.UID)
		return false
	}
	//This check ensures that the TID in the workflow corresponds to one of
	//the txns that is supported by our unit. Not sure if we also need to
	//check whether the name of the txn matches the API call
	if _, ok := storageData.Txns[myWfNode.TID]; !ok {
		log.Errorf("Invalid TID: %s", myWfNode.TID)
		return false
	}

	//STEP 3: Check the dependencies
	for _, depIdx := range myWfNode.Deps {
		depUID := v.Plan.Workflow[depIdx].UID
		sig := v.SigMap[depIdx]
		err = sig.Verify(suite, payload, v.Plan.Publics[depUID].Keys)
		if err != nil {
			log.Errorf("Cannot verify the signature of UID: %s", depUID)
			return false
		}
	}
	return true
}

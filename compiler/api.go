package compiler

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

type Client struct {
	*onet.Client
	roster *onet.Roster
}

func NewClient(r *onet.Roster) *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName), roster: r}
}

func (c *Client) InitUnit(scCfg *sys.ScConfig) (*InitUnitReply, error) {
	req := &InitUnitRequest{
		Roster: c.roster,
		ScCfg:  scCfg,
	}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) StoreGenesis(who *network.ServerIdentity, genesis skipchain.SkipBlockID) error {
	req := &StoreGenesisRequest{
		Genesis: genesis,
	}
	reply := &StoreGenesisReply{}
	err := c.SendProtobuf(who, req, reply)
	return err
}

func (c *Client) CreateUnits(units []*sys.FunctionalUnit) (*CreateUnitsReply, error) {
	req := &CreateUnitsRequest{
		Units: units,
	}
	reply := &CreateUnitsReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

//func (c *Client) GenerateExecutionPlan(wf *sys.Workflow, keyStrs []string, sigs [][]byte) (*ExecutionPlanReply, error) {
func (c *Client) GenerateExecutionPlan(wf *sys.Workflow) (*ExecutionPlanReply, error) {
	//sigMap := make(map[string][]byte)
	//if len(keyStrs) != len(sigs) {
	//return nil, fmt.Errorf("Number of keys and sigs do not match")
	//}
	//if len(keyStrs) == 0 {
	//sigMap = nil
	//} else {
	//for i, key := range keyStrs {
	//sigMap[key] = sigs[i]
	//}
	//}
	req := &ExecutionPlanRequest{
		Workflow: wf,
		//SigMap:   sigMap,
	}
	reply := &ExecutionPlanReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) GetDirectoryInfo() (*DirectoryInfoReply, error) {
	req := &DirectoryInfoRequest{}
	reply := &DirectoryInfoReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func PrepareWorkflow(wFilePtr *string, dirInfo map[string]*sys.UnitInfo) (*sys.Workflow, error) {
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
			tid, found := unitInfo.Txns[tmp.TxnName]
			if found {
				wfNodes[i] = &sys.WfNode{
					UID:  unitInfo.UnitID,
					TID:  tid,
					Deps: tmp.Deps,
				}
			} else {
				log.Errorf("Txn %v not found for unit %v", tmp.TxnName, tmp.UnitName)
				return nil, errors.New("No transaction found for the given unit")
			}
		} else {
			log.Errorf("Unit does not exist")
			return nil, errors.New("Unit does not exist")
		}
	}

	//var authPublics map[string]kyber.Point
	//if publics != nil {
	//authPublics = make(map[string]kyber.Point)
	//for _, pk := range publics {
	//authPublics[pk.String()] = pk
	//}
	//}
	//return &sys.Workflow{Nodes: wfNodes, AuthPublics: authPublics, All: all}, nil
	return &sys.Workflow{Nodes: wfNodes}, nil
}

func PrepareExecutionData(planReply *ExecutionPlanReply) *sys.ExecutionData {
	return &sys.ExecutionData{
		Index:       0,
		ExecPlan:    planReply.ExecPlan,
		CompilerSig: planReply.Signature,
		UnitSigs:    make([]protocol.BlsSignature, len(planReply.ExecPlan.Workflow.Nodes)),
	}
}

func GetServiceID() onet.ServiceID {
	return compilerID
}

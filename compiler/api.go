package compiler

import (
	"fmt"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

type Client struct {
	*onet.Client
	roster *onet.Roster
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}

func (c *Client) InitUnit(roster *onet.Roster, scCfg *sys.ScConfig) (*InitUnitReply, error) {
	c.roster = roster
	req := &InitUnitRequest{
		Roster: roster,
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

func (c *Client) GenerateExecutionPlan(wf *sys.Workflow, keyStrs []string, sigs [][]byte) (*ExecutionPlanReply, error) {
	sigMap := make(map[string][]byte)
	if len(keyStrs) != len(sigs) {
		return nil, fmt.Errorf("Number of keys and sigs do not match")
	}
	if len(keyStrs) == 0 {
		sigMap = nil
	} else {
		for i, key := range keyStrs {
			sigMap[key] = sigs[i]
		}
	}
	req := &ExecutionPlanRequest{
		Workflow: wf,
		SigMap:   sigMap,
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

func SignWorkflow(wf *sys.Workflow, sk kyber.Scalar) ([]byte, error) {
	wfHash, err := utils.ComputeWFHash(wf)
	if err != nil {
		return nil, fmt.Errorf("Sign workflow failed with protobuf error: %v", err)
	}
	sig, err := schnorr.Sign(cothority.Suite, sk, wfHash)
	if err != nil {
		return nil, fmt.Errorf("Cannot sign the workflow: %v", err)
	}
	return sig, nil
}

func GetServiceID() onet.ServiceID {
	return compilerID
}

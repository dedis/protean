package compiler

import (
	"fmt"

	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/skipchain"
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

//func (c *Client) InitUnit(roster *onet.Roster, scData *sys.ScInitData) (*InitUnitReply, error) {
func (c *Client) InitUnit(roster *onet.Roster, scCfg *sys.ScConfig) (*InitUnitReply, error) {
	c.roster = roster
	req := &InitUnitRequest{
		Roster: roster,
		//ScData: scData,
		ScCfg: scCfg,
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

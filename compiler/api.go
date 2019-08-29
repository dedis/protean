package compiler

import (
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

//func (c *Client) InitUnit(roster *onet.Roster, scData *protean.ScInitData) (*InitUnitReply, error) {
func (c *Client) InitUnit(roster *onet.Roster, scData *sys.ScInitData) (*InitUnitReply, error) {
	c.roster = roster
	req := &InitUnitRequest{
		Roster: roster,
		ScData: scData,
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

//func (c *Client) GenerateExecutionPlan(wf []*protean.WfNode) (*ExecutionPlanReply, error) {
func (c *Client) GenerateExecutionPlan(wf []*sys.WfNode) (*ExecutionPlanReply, error) {
	req := &ExecutionPlanRequest{
		Workflow: wf,
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

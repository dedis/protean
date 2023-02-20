package libstate

import (
	"github.com/dedis/protean/contracts"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libstate/base"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"time"
)

type AdminClient struct {
	Cl   *Client
	GMsg *byzcoin.CreateGenesisBlock
}

type Client struct {
	bcClient *byzcoin.Client
	c        *onet.Client
	signer   darc.Signer
	ctr      uint64
}

func NewAdminClient(byzcoin *byzcoin.Client, signer darc.Signer,
	gMsg *byzcoin.CreateGenesisBlock) *AdminClient {
	return &AdminClient{Cl: &Client{bcClient: byzcoin,
		c: onet.NewClient(cothority.Suite, ServiceName), signer: signer,
		ctr: uint64(1)}, GMsg: gMsg}
}

func NewClient(byzcoin *byzcoin.Client, signer darc.Signer) *Client {
	return &Client{bcClient: byzcoin, c: onet.NewClient(cothority.Suite,
		ServiceName), signer: signer, ctr: uint64(1)}
}

func SetupByzcoin(r *onet.Roster, blockTime time.Duration) (*AdminClient,
	skipchain.SkipBlockID, error) {
	signer := darc.NewSignerEd25519(nil, nil)
	gMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, r, []string{"spawn:keyValue", "invoke:keyValue.update"}, signer.Identity())
	if err != nil {
		return nil, nil, err
	}
	gMsg.BlockInterval = blockTime * time.Second
	c, _, err := byzcoin.NewLedger(gMsg, true)
	if err != nil {
		return nil, nil, err
	}
	cl := NewAdminClient(c, signer, gMsg)
	return cl, c.ID, nil
}

func (c *Client) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	reply := &InitUnitReply{}
	for _, node := range c.bcClient.Roster.List {
		err := c.c.SendProtobuf(node, req, reply)
		if err != nil {
			return nil, xerrors.Errorf("send InitUnit message: %v", err)
		}
	}
	return reply, nil
}

func (c *Client) InitContract(hdr *core.ContractHeader, initArgs byzcoin.Arguments, wait int) (*InitContractReply, error) {
	reply := &InitContractReply{}
	req := &InitContractRequest{
		Header:   hdr,
		InitArgs: initArgs,
		Wait:     wait,
	}
	err := c.c.SendProtobuf(c.bcClient.Roster.List[0], req, reply)
	if err != nil {
		return nil, xerrors.Errorf("initializing contract: %v", err)
	}
	return reply, nil
}

func (c *Client) GetState(cid byzcoin.InstanceID) (*GetStateReply, error) {
	reply := &GetStateReply{}
	req := &GetStateRequest{CID: cid}
	err := c.c.SendProtobuf(c.bcClient.Roster.List[0], req, reply)
	if err != nil {
		return nil, xerrors.Errorf("sending get contract state message: %v", err)
	}
	return reply, nil
}

func (c *Client) UpdateState(args byzcoin.Arguments,
	execReq *core.ExecutionRequest, wait int) (*UpdateStateReply, error) {
	reply := &UpdateStateReply{}
	req := &UpdateStateRequest{
		Input:   base.UpdateInput{Args: args},
		ExecReq: *execReq,
		Wait:    wait,
	}
	err := c.c.SendProtobuf(c.bcClient.Roster.List[0], req, reply)
	if err != nil {
		return nil, xerrors.Errorf("update state: %v", err)
	}
	return reply, nil
}

// FetchGenesisBlock requires the hash of the genesis block. To retrieve,
// use proof.Latest.SkipchainID()
func (c *Client) FetchGenesisBlock(scID skipchain.SkipBlockID) (*skipchain.
	SkipBlock, error) {
	cl := skipchain.NewClient()
	sb, err := cl.GetSingleBlock(&c.bcClient.Roster, scID)
	if err != nil {
		return nil, xerrors.Errorf("getting genesis block: %v", err)
	}
	return sb, nil
}

func (c *AdminClient) SpawnDarc(newSigner darc.Signer, gDarc darc.Darc, wait int) (*darc.Darc, error) {
	d := darc.NewDarc(darc.InitRules([]darc.Identity{newSigner.Identity()},
		[]darc.Identity{newSigner.Identity()}), []byte("stateroot"))
	d.Rules.AddRule(darc.Action("spawn:"+contracts.ContractKeyValueID),
		expression.InitOrExpr(newSigner.Identity().String()))
	d.Rules.AddRule(darc.Action("invoke:"+contracts.ContractKeyValueID+"."+
		"update"), expression.InitOrExpr(newSigner.Identity().String()))
	darcBuf, err := d.ToProto()
	if err != nil {
		log.Errorf("serializing darc to protobuf: %v", err)
		return nil, err
	}
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: byzcoin.ContractDarcID,
				Args: []byzcoin.Argument{{
					Name:  "darc",
					Value: darcBuf,
				}},
			},
			SignerCounter: []uint64{c.Cl.ctr},
		},
	)
	err = ctx.FillSignersAndSignWith(c.Cl.signer)
	if err != nil {
		return nil, xerrors.Errorf("signing txn: %v", err)
	}
	_, err = c.Cl.bcClient.AddTransactionAndWait(ctx, wait)
	c.Cl.ctr++
	return d, cothority.ErrorOrNil(err, "adding txn")
}

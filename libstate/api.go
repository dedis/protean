package libstate

import (
	"bytes"
	"time"

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
)

type AdminClient struct {
	Cl     *Client
	GMsg   *byzcoin.CreateGenesisBlock
	signer darc.Signer
	ctr    uint64
}

type Client struct {
	bcClient *byzcoin.Client
	c        *onet.Client
}

func NewAdminClient(byzcoin *byzcoin.Client, signer darc.Signer,
	gMsg *byzcoin.CreateGenesisBlock) *AdminClient {
	return &AdminClient{Cl: &Client{bcClient: byzcoin,
		c: onet.NewClient(cothority.Suite, ServiceName)}, signer: signer,
		ctr: uint64(1), GMsg: gMsg}
}

func NewClient(byzcoin *byzcoin.Client) *Client {
	return &Client{bcClient: byzcoin, c: onet.NewClient(cothority.Suite, ServiceName)}
}

func SetupByzcoin(r *onet.Roster, blockTime int) (*AdminClient,
	skipchain.SkipBlockID, error) {
	signer := darc.NewSignerEd25519(nil, nil)
	gMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, r,
		[]string{"spawn:keyValue", "invoke:keyValue.init_contract",
			"invoke:keyValue.update", "invoke:keyValue.dummy"},
		signer.Identity())
	if err != nil {
		return nil, nil, err
	}
	gMsg.BlockInterval = time.Duration(blockTime) * time.Second
	//c, _, err := byzcoin.NewLedger(gMsg, true)
	c, _, err := byzcoin.NewLedger(gMsg, false)
	if err != nil {
		return nil, nil, err
	}
	cl := NewAdminClient(c, signer, gMsg)
	return cl, c.ID, nil
}

func (c *Client) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	reply := &InitUnitReply{}
	err := c.c.SendProtobuf(c.bcClient.Roster.List[0], req, reply)
	if err != nil {
		return nil, xerrors.Errorf("send InitUnit message: %v", err)
	}
	return reply, nil
}

func (c *Client) InitContract(raw *core.ContractRaw, hdr *core.ContractHeader,
	initArgs byzcoin.Arguments, wait int) (*InitContractReply, error) {
	reply := &InitContractReply{}
	req := &InitContractRequest{
		Raw:      raw,
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

func (c *Client) GetState(cid byzcoin.InstanceID) (*GetStateReply,
	error) {
	reply := &GetStateReply{}
	req := &GetStateRequest{CID: cid}
	err := c.c.SendProtobuf(c.bcClient.Roster.List[0], req, reply)
	if err != nil {
		return nil, xerrors.Errorf("sending get contract state message: %v", err)
	}
	return reply, nil
}

func (c *Client) UpdateState(args byzcoin.Arguments,
	execReq *core.ExecutionRequest, inReceipts map[int]map[string]*core.
		OpcodeReceipt, wait int) (*UpdateStateReply, error) {
	reply := &UpdateStateReply{}
	req := &UpdateStateRequest{
		Input:         base.UpdateInput{Args: args},
		ExecReq:       *execReq,
		Wait:          wait,
		InputReceipts: inReceipts,
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
	d.Rules.AddRule("spawn:"+contracts.ContractKeyValueID,
		expression.InitOrExpr(newSigner.Identity().String()))
	d.Rules.AddRule("invoke:"+contracts.ContractKeyValueID+"."+
		"init_contract", expression.InitOrExpr(newSigner.Identity().String()))
	d.Rules.AddRule("invoke:"+contracts.ContractKeyValueID+"."+
		"update", expression.InitOrExpr(newSigner.Identity().String()))
	d.Rules.AddRule("invoke:"+contracts.ContractKeyValueID+"."+
		"dummy", expression.InitOrExpr(newSigner.Identity().String()))
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
			SignerCounter: []uint64{c.ctr},
		},
	)
	err = ctx.FillSignersAndSignWith(c.signer)
	if err != nil {
		return nil, xerrors.Errorf("signing txn: %v", err)
	}
	_, err = c.Cl.bcClient.AddTransactionAndWait(ctx, wait)
	c.ctr++
	return d, cothority.ErrorOrNil(err, "adding txn")
}

func (c *Client) WaitProof(id []byte, currRoot []byte, interval int) (
	*byzcoin.Proof, error) {
	var pr byzcoin.Proof
	for i := 0; i < 10; i++ {
		// try to get the darc back, we should get the genesis back instead
		resp, err := c.bcClient.GetProof(id)
		if err != nil {
			log.Warnf("Error while getting proof: %+v", err)
			continue
		}
		pr = resp.Proof
		ok, err := pr.InclusionProof.Exists(id)
		if err != nil {
			return nil, xerrors.Errorf(
				"inclusion proof couldn't be checked: %+v", err)
		}
		if ok {
			if !bytes.Equal(currRoot, pr.InclusionProof.GetRoot()) {
				return &pr, nil
			}
		}

		// wait for the block to be processed
		//time.Sleep((time.Duration(interval) * time.Second) / 5)
		time.Sleep((time.Duration(interval) * time.Second) / 3)
	}
	return nil, xerrors.New("timeout reached and proof not found")
}

func (c *Client) DummyUpdate(cid byzcoin.InstanceID, args byzcoin.Arguments,
	wait int) (*DummyReply, error) {
	reply := &DummyReply{}
	req := &DummyRequest{
		CID:   cid,
		Input: base.UpdateInput{Args: args},
		Wait:  wait,
	}
	err := c.c.SendProtobuf(c.bcClient.Roster.List[0], req, reply)
	if err != nil {
		return nil, xerrors.Errorf("dummy update: %v", err)
	}
	return reply, nil
}

func (c *Client) DummyGetProof(cid byzcoin.InstanceID) (*byzcoin.GetProofResponse, error) {
	return c.bcClient.GetProof(cid[:])
}

func (c *Client) Close() error {
	return c.c.Close()
}

package libstate

import (
	"github.com/dedis/protean/contracts"
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/protobuf"
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
	//c, _, err := byzcoin.NewLedger(gMsg, false)
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

func (c *Client) InitContract(hdr *core.ContractHeader, gDarc darc.Darc,
	wait int) (*InitContractReply, error) {
	hdrBuf, err := protobuf.Encode(hdr)
	if err != nil {
		return nil, xerrors.Errorf("encoding contract header: %v", err)
	}
	//args := byzcoin.Arguments{{Name: "header", Value: hdrBuf},
	//	{Name: "kvstore", Value: []byte{}}}
	args := byzcoin.Arguments{{Name: "header", Value: hdrBuf}}
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: contracts.ContractKeyValueID,
				Args:       args,
			},
			SignerCounter: []uint64{c.ctr},
		})
	err = ctx.FillSignersAndSignWith(c.signer)
	if err != nil {
		return nil, xerrors.Errorf("signing transaction: %v", err)
	}
	cid := ctx.Instructions[0].DeriveID("")
	_, err = c.bcClient.AddTransactionAndWait(ctx, wait)
	if err != nil {
		return nil, xerrors.Errorf("adding transaction: %v", err)
	}
	c.ctr++
	// Store CID in header
	hdr.CID = cid
	hdrBuf, err = protobuf.Encode(hdr)
	if err != nil {
		return nil, xerrors.Errorf("encoding contract header: %v", err)
	}
	args[0].Value = hdrBuf
	ctx = byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: cid,
			Invoke: &byzcoin.Invoke{
				ContractID: contracts.ContractKeyValueID,
				Command:    "update",
				Args:       args,
			},
			SignerCounter: []uint64{c.ctr},
		})
	err = ctx.FillSignersAndSignWith(c.signer)
	if err != nil {
		return nil, xerrors.Errorf("adding update transaction: %v", err)
	}
	reply := &InitContractReply{CID: cid}
	reply.TxResp, err = c.bcClient.AddTransactionAndWait(ctx, wait)
	if err != nil {
		return nil, xerrors.Errorf("adding transaction: %v", err)
	}
	c.ctr++
	return reply, err
}

func (c *Client) GetContractState(cid byzcoin.InstanceID) (*GetContractStateReply, error) {
	reply := &GetContractStateReply{}
	req := &GetContractState{CID: cid}
	err := c.c.SendProtobuf(c.bcClient.Roster.List[0], req, reply)
	if err != nil {
		return nil, xerrors.Errorf("send get contract state message: %v", err)
	}
	return reply, nil
}

func (c *Client) UpdateState(cid byzcoin.InstanceID, args byzcoin.Arguments) (*UpdateStateReply, error) {
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: cid,
			Invoke: &byzcoin.Invoke{
				ContractID: contracts.ContractKeyValueID,
				Command:    "update",
				Args:       args,
			},
			SignerCounter: []uint64{c.ctr},
		})
	err := ctx.FillSignersAndSignWith(c.signer)
	if err != nil {
		return nil, xerrors.Errorf("signing transaction: %v", err)
	}

	//reply := &UpdateStateReply{CID: cid}
	//reply.TxResp, err = c.bcClient.AddTransactionAndWait(ctx, wait)
	_, err = c.bcClient.AddTransaction(ctx)
	if err != nil {
		return nil, xerrors.Errorf("adding transaction")
	}
	return &UpdateStateReply{}, nil
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

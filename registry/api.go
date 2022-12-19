package registry

import (
	"github.com/dedis/protean/contracts"
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"

	"time"
)

type AdminClient struct {
	Cl     *Client
	signer darc.Signer
	ctr    uint64
	gMsg   *byzcoin.CreateGenesisBlock
}

type Client struct {
	bcClient *byzcoin.Client
	//c        *onet.Client
}

type InitRegistryReply struct {
	IID    byzcoin.InstanceID
	TxResp *byzcoin.AddTxResponse
}

func NewAdminClient(byzcoin *byzcoin.Client, signer darc.Signer,
	ctr uint64, gMsg *byzcoin.CreateGenesisBlock) *AdminClient {
	return &AdminClient{Cl: &Client{bcClient: byzcoin}, signer: signer, ctr: ctr, gMsg: gMsg}
	//return &AdminClient{Cl: &Client{bcClient: byzcoin, c: onet.NewClient(cothority.
	//		Suite, ServiceName)}, signer: signer, ctr: ctr, gMsg: gMsg}
}

func NewClient(byzcoin *byzcoin.Client) *Client {
	return &Client{bcClient: byzcoin}
	//return &Client{bcClient: byzcoin, c: onet.NewClient(cothority.Suite,
	//	ServiceName)}
}

func SetupByzcoin(r *onet.Roster, blockTime time.Duration) (*AdminClient, skipchain.SkipBlockID, error) {
	signer := darc.NewSignerEd25519(nil, nil)
	gMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, r, []string{"spawn:keyValue", "invoke:keyValue.update"}, signer.Identity())
	if err != nil {
		return nil, nil, err
	}
	gMsg.BlockInterval = blockTime * time.Second
	c, _, err := byzcoin.NewLedger(gMsg, false)
	if err != nil {
		return nil, nil, err
	}
	cl := NewAdminClient(c, signer, uint64(1), gMsg)
	return cl, c.ID, nil
}

func (c *AdminClient) InitRegistry(registry *core.DFURegistry, wait int) (*InitRegistryReply, error) {
	buf, err := protobuf.Encode(registry)
	if err != nil {
		return nil, xerrors.Errorf("encoding DFU registry: %v", err)
	}
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: byzcoin.NewInstanceID(c.gMsg.GenesisDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: contracts.ContractKeyValueID,
				Args: byzcoin.Arguments{{
					Name: "registry", Value: buf}},
			},
			SignerCounter: []uint64{c.ctr},
		},
	)
	err = ctx.FillSignersAndSignWith(c.signer)
	if err != nil {
		return nil, xerrors.Errorf("signing txn: %v", err)
	}
	reply := &InitRegistryReply{IID: ctx.Instructions[0].DeriveID("")}
	reply.TxResp, err = c.Cl.bcClient.AddTransactionAndWait(ctx, wait)
	if err != nil {
		return nil, xerrors.Errorf("adding txn: %v", err)
	}
	return reply, nil
}

func (c *Client) WaitProof(id byzcoin.InstanceID, interval time.Duration,
	value []byte) (*byzcoin.Proof, error) {
	return c.bcClient.WaitProof(id, interval, value)
}

func (c *Client) FetchGenesisBlock(scID skipchain.SkipBlockID) (*skipchain.
	SkipBlock, error) {
	cl := skipchain.NewClient()
	sb, err := cl.GetSingleBlock(&c.bcClient.Roster, scID)
	if err != nil {
		return nil, xerrors.Errorf("getting genesis block: %v", err)
	}
	return sb, nil
}

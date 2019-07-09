package state

import (
	"github.com/ceyhunalp/protean_code"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

type Client struct {
	bcClient *byzcoin.Client
	cl       *onet.Client
}

func NewClient(byzCl *byzcoin.Client) *Client {
	return &Client{
		bcClient: byzCl,
		cl:       onet.NewClient(cothority.Suite, ServiceName),
	}
}

func (c *Client) SetKV(kvBuf []byte, signer darc.Signer, signerCtr uint64, darc darc.Darc, wait int) (reply *SetKVReply, err error) {
	reply = &SetKVReply{}
	if err != nil {
		return nil, err
	}

	ctx := byzcoin.ClientTransaction{
		Instructions: byzcoin.Instructions{{
			InstanceID: byzcoin.NewInstanceID(darc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: ContractKeyValueID,
				Args: byzcoin.Arguments{{
					Name: "set", Value: kvBuf}},
			},
			SignerCounter: []uint64{signerCtr},
		}},
	}

	err = ctx.FillSignersAndSignWith(signer)
	if err != nil {
		return nil, err
	}
	reply.InstanceID = ctx.Instructions[0].DeriveID("")
	reply.AddTxResponse, err = c.bcClient.AddTransactionAndWait(ctx, wait)
	if err != nil {
		return nil, err
	}
	return reply, err
}

func (c *Client) InitUnitRequest(dst *network.ServerIdentity, uid string, txns map[string]string, publics []kyber.Point) error {
	req := &protean.InitUnitRequest{
		CompilerKeys: publics,
		UnitID:       uid,
		Txns:         txns,
	}
	err := c.cl.SendProtobuf(dst, req, nil)
	return err
}

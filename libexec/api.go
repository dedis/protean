package libexec

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"golang.org/x/xerrors"
)

type Client struct {
	*onet.Client
	roster *onet.Roster
}

func NewClient(r *onet.Roster) *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName), roster: r}
}

func (c *Client) InitTransaction(cid byzcoin.InstanceID, rid byzcoin.InstanceID,
	regProof *byzcoin.Proof, regGenesis *skipchain.SkipBlock,
	stateProof *core.StateProof, stateGenesis *skipchain.SkipBlock, wf string,
	txn string) (*InitTransactionReply, error) {
	reply := &InitTransactionReply{}
	req := &InitTransaction{
		RData: RegistryData{
			RID:             rid,
			RegistryProof:   *regProof,
			RegistryGenesis: *regGenesis,
		},
		CData: ContractData{
			CID:          cid,
			StateProof:   *stateProof,
			StateGenesis: *stateGenesis,
		},
		WfName:  wf,
		TxnName: txn,
	}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	if err != nil {
		return nil, xerrors.Errorf("sending init transaction message: %v", err)
	}
	return reply, nil
}

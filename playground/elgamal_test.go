package playground

import (
	"testing"
	"time"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/threshold"
	"github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

func TestElGamal(t *testing.T) {
	// Create a new ledger and prepare for proper closing
	egt := newEGTest(t)
	defer egt.local.CloseAll()

	scData, uData := prepareUnitData(egt.roster)

	keypair := darc.NewSignerEd25519(nil, nil)

	sig, err := keypair.Sign([]byte("thresh-test"))
	require.Nil(t, err)
	log.Info("Length is:", len(sig))
	log.Info("Sig is:", sig)

	client := threshold.NewClient()
	_, err = client.InitUnit(egt.roster, scData, uData, 10, time.Second)
	require.Nil(t, err)
	dkgReply, err := client.InitDKG(sig)
	require.Nil(t, err)

	mesgs, cs := prepareMessages(dkgReply.X)
	decReply, err := client.Decrypt(sig, cs, false)
	require.Nil(t, err)

	instID := egt.createInstance(t, len(egt.roster.List), cs, decReply.Partials)
	pr, err := egt.cl.WaitProof(instID, egt.gMsg.BlockInterval*2, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(instID.Slice()))

	//// Get the raw values of the proof.
	_, val, _, _, err := pr.KeyValue()
	require.Nil(t, err)
	st := ElGamalStorage{}
	err = protobuf.Decode(val, &st)
	require.Nil(t, err)
	for i, s := range st.Storage {
		//require.Equal(t, cs[i].K, s.Cs[i].K)
		//require.Equal(t, cs[i].C, s.Cs[i].C)
		require.Equal(t, string(mesgs[i]), s.Ps[i])
	}
}

func prepareMessages(X kyber.Point) ([][]byte, []*utils.ElGamalPair) {
	var mesgs [][]byte
	mesgs = append(mesgs, []byte("Robert Glasper"))
	mesgs = append(mesgs, []byte("Lionel Loueke"))
	mesgs = append(mesgs, []byte("Christian Scott"))
	mesgs = append(mesgs, []byte("Dave Weckl"))
	var cs []*utils.ElGamalPair
	for _, mesg := range mesgs {
		c := utils.ElGamalEncrypt(X, mesg)
		cs = append(cs, &c)
	}
	return mesgs, cs
}

func prepareUnitData(roster *onet.Roster) (*sys.ScConfig, *sys.BaseStorage) {
	scCfg := &sys.ScConfig{
		MHeight: 2,
		BHeight: 2,
	}
	baseStore := &sys.BaseStorage{
		UnitID:      "threshold",
		UnitName:    "thresholdUnit",
		Txns:        map[string]string{"a": "b", "c": "d"},
		CompPublics: roster.ServicePublics(threshold.ServiceName),
	}
	return scCfg, baseStore
}

// egTest is used here to provide some simple test structure for different
// tests.
type egTest struct {
	local    *onet.LocalTest
	services []*blscosi.Service
	signer   darc.Signer
	servers  []*onet.Server
	roster   *onet.Roster
	cl       *byzcoin.Client
	gMsg     *byzcoin.CreateGenesisBlock
	gDarc    *darc.Darc
	ct       uint64
}

func newEGTest(t *testing.T) (out *egTest) {
	out = &egTest{}
	out.local = onet.NewTCPTest(cothority.Suite)
	out.signer = darc.NewSignerEd25519(nil, nil)
	out.servers, out.roster, _ = out.local.GenTree(4, true)
	//services := out.local.GetServices(out.servers, blscosi.ServiceID)
	//for _, ser := range services {
	//out.services = append(out.services, ser.(*blscosi.Service))
	//}
	var err error
	out.gMsg, err = byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, out.roster,
		[]string{"spawn:" + ContractElGamalID}, out.signer.Identity())
	require.Nil(t, err)
	out.gDarc = &out.gMsg.GenesisDarc
	out.gMsg.BlockInterval = time.Second * 20

	out.cl, _, err = byzcoin.NewLedger(out.gMsg, false)
	require.Nil(t, err)
	out.ct = 1

	return out
}

func (egt *egTest) Close() {
	egt.local.CloseAll()
}

func (egt *egTest) createInstance(t *testing.T, numNodes int, cs []*utils.ElGamalPair, partials []*threshold.Partial) byzcoin.InstanceID {
	req := &ReconstructRequest{
		NumNodes: numNodes,
		Cs:       cs,
		Partials: partials,
	}
	buf, err := protobuf.Encode(req)
	require.Nil(t, err)
	args := byzcoin.Arguments{
		{
			Name:  "reconstruct",
			Value: buf,
		},
	}
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion, byzcoin.Instruction{
		InstanceID:    byzcoin.NewInstanceID(egt.gDarc.GetBaseID()),
		SignerCounter: []uint64{egt.ct},
		Spawn: &byzcoin.Spawn{
			ContractID: ContractElGamalID,
			Args:       args,
		},
	})
	egt.ct++
	require.NoError(t, ctx.FillSignersAndSignWith(egt.signer))
	_, err = egt.cl.AddTransactionAndWait(ctx, 5)
	require.Nil(t, err)
	return ctx.Instructions[0].DeriveID("")
}

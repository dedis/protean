package libexec

import (
	"flag"
	"fmt"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libstate"
	"github.com/dedis/protean/registry"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"testing"
	"time"
)

var baseFile string
var contractFile string
var fsmFile string
var dfuFile string

var testSuite = pairing.NewSuiteBn256()

func init() {
	flag.StringVar(&baseFile, "base", "", "JSON file")
	flag.StringVar(&fsmFile, "fsm", "", "JSON file")
	flag.StringVar(&dfuFile, "dfu", "", "JSON file")
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func setupRegistry(roster *onet.Roster) (*registry.Client, byzcoin.InstanceID, *byzcoin.Proof, error) {
	var id byzcoin.InstanceID
	dfuReg, err := libclient.ReadDFUJSON(&dfuFile)
	if err != nil {
		return nil, id, nil, err
	}
	for k := range dfuReg.Units {
		dfuReg.Units[k].Keys = roster.Publics()
	}

	adminCl, byzID, err := registry.SetupByzcoin(roster, 1)
	if err != nil {
		return nil, id, nil, err
	}
	reply, err := adminCl.InitRegistry(dfuReg, 3)
	if err != nil {
		return nil, id, nil, err
	}
	pr, err := adminCl.Cl.WaitProof(reply.IID, 2*time.Second, nil)
	if err != nil {
		return nil, id, nil, err
	}

	bc := byzcoin.NewClient(byzID, *roster)
	cl := registry.NewClient(bc)
	return cl, reply.IID, pr, nil
}

func setupStateUnit(roster *onet.Roster) (*libstate.AdminClient, error) {
	adminCl, byzID, err := libstate.SetupByzcoin(roster, 1)
	if err != nil {
		return nil, err
	}
	req := &libstate.InitUnitRequest{
		ByzID:  byzID,
		Roster: roster,
	}
	_, err = adminCl.Cl.InitUnit(req)
	if err != nil {
		return nil, err
	}
	return adminCl, nil
}

func Test_InitTransaction(t *testing.T) {
	l := onet.NewTCPTest(cothority.Suite)
	_, all, _ := l.GenTree(14, true)
	defer l.CloseAll()
	regRoster := onet.NewRoster(all.List[0:7])
	stateRoster := onet.NewRoster(all.List[7:])
	regCl, rid, regPr, err := setupRegistry(regRoster)
	require.NoError(t, err)
	regGenesis, err := regCl.FetchGenesisBlock(regPr.Latest.SkipChainID())
	require.NoError(t, err)
	adminCl, err := setupStateUnit(stateRoster)
	require.NoError(t, err)

	contract, err := libclient.ReadContractJSON(&baseFile)
	require.NoError(t, err)

	fsm, err := libclient.ReadFSMJSON(&fsmFile)
	require.NoError(t, err)

	hdr := &core.ContractHeader{
		Contract:  contract,
		FSM:       fsm,
		CodeHash:  []byte("codehash"),
		Lock:      nil,
		CurrState: fsm.InitialState,
	}

	reply, err := adminCl.Cl.InitContract(hdr, adminCl.GMsg.GenesisDarc, 10)
	cid := reply.CID
	require.NoError(t, err)
	stGenesis, err := adminCl.Cl.FetchGenesisBlock(reply.TxResp.Proof.
		Latest.SkipChainID())
	require.NoError(t, err)
	execCl := NewClient(stateRoster)
	_, err = execCl.InitUnit()
	require.NoError(t, err)
	require.NotNil(t, reply.TxResp.Proof)

	gcs, err := adminCl.Cl.GetState(cid)
	require.NoError(t, err)
	rdata := ByzData{
		IID:     rid,
		Proof:   *regPr,
		Genesis: *regGenesis,
	}
	cdata := ByzData{
		IID:     cid,
		Proof:   gcs.Proof.Proof,
		Genesis: *stGenesis,
	}
	itReply, err := execCl.InitTransaction(rdata, cdata, "vote", "cast_vote")
	require.NoError(t, err)
	require.NotNil(t, itReply)
	fmt.Println(itReply.Plan.String())
}

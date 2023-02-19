package libstate

import (
	"flag"
	"fmt"
	"github.com/dedis/protean/contracts"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	"github.com/dedis/protean/registry"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

var contractFile string
var fsmFile string
var dfuFile string

var testSuite = pairing.NewSuiteBn256()

func init() {
	flag.StringVar(&contractFile, "contract", "", "JSON file")
	flag.StringVar(&fsmFile, "fsm", "", "JSON file")
	flag.StringVar(&dfuFile, "dfu", "", "JSON file")
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func setupRegistry(regRoster *onet.Roster, dfuRoster *onet.Roster) (*registry.
	Client, byzcoin.InstanceID, *byzcoin.Proof, error) {
	var id byzcoin.InstanceID
	dfuReg, err := libclient.ReadDFUJSON(&dfuFile)
	if err != nil {
		return nil, id, nil, err
	}
	for k := range dfuReg.Units {
		if k == "easyneff" || k == "threshold" || k == "easyrand" {
			dfuReg.Units[k].Keys = dfuRoster.ServicePublics(blscosi.ServiceName)
		} else if k == "codeexec" {
			dfuReg.Units[k].Keys = dfuRoster.ServicePublics(libexec.ServiceName)
		} else if k == "state" {
			//TODO: Check this
			dfuReg.Units[k].Keys = dfuRoster.ServicePublics(skipchain.ServiceName)
		} else {
			os.Exit(1)
		}
	}

	adminCl, byzID, err := registry.SetupByzcoin(regRoster, 1)
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

	bc := byzcoin.NewClient(byzID, *regRoster)
	cl := registry.NewClient(bc)
	return cl, reply.IID, pr, nil
}

func setupStateUnit(roster *onet.Roster) (*AdminClient, error) {
	adminCl, byzID, err := SetupByzcoin(roster, 3)
	if err != nil {
		return nil, err
	}
	req := &InitUnitRequest{
		ByzID:  byzID,
		Roster: roster,
	}
	_, err = adminCl.Cl.InitUnit(req)
	if err != nil {
		return nil, err
	}
	return adminCl, nil
}

type Votes struct {
	Votes []Vote
}

type Vote struct {
	Name   string
	Choice int
}

func prepareVotes() Votes {
	vs := make([]Vote, 10)
	for i := 0; i < 10; i++ {
		vs[i].Name = "Vote " + strconv.Itoa(i)
		vs[i].Choice = i
	}
	return Votes{Votes: vs}
}

func Test_AddKV(t *testing.T) {
	log.SetDebugVisible(1)
	l := onet.NewTCPTest(cothority.Suite)
	_, all, _ := l.GenTree(14, true)
	defer l.CloseAll()
	regRoster := onet.NewRoster(all.List[0:4])
	dfuRoster := onet.NewRoster(all.List[4:])

	//regCl, rid, regPr, err := setupRegistry(regRoster, dfuRoster)
	regCl, _, regPr, err := setupRegistry(regRoster, dfuRoster)
	require.NoError(t, err)
	//regGenesis, err := regCl.FetchGenesisBlock(regPr.Latest.SkipChainID())
	_, err = regCl.FetchGenesisBlock(regPr.Latest.SkipChainID())
	require.NoError(t, err)

	// Initialize DFUs
	stateCl, err := setupStateUnit(dfuRoster)
	require.NoError(t, err)

	// Client-side operations: read JSON files
	contract, err := libclient.ReadContractJSON(&contractFile)
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

	// Initialize contract (state unit)
	reply, err := stateCl.Cl.InitContract(hdr, stateCl.GMsg.GenesisDarc, 10)
	require.NotNil(t, reply)
	require.NoError(t, err)
	cid := reply.CID

	fmt.Println("Before update:", reply.TxResp.Proof.InclusionProof.GetRoot())

	votes := prepareVotes()
	buf, err := protobuf.Encode(&votes)
	require.NoError(t, err)
	args := byzcoin.Arguments{{Name: "votes", Value: buf}}
	_, err = stateCl.Cl.UpdateState(reply.CID, args)
	require.NoError(t, err)

	//time.Sleep(5 * time.Second)

	gcs, err := stateCl.Cl.GetState(cid)
	require.NoError(t, err)
	v, _, _, err := gcs.Proof.Proof.Get(cid.Slice())
	require.NoError(t, err)

	fmt.Println("After gcs:", gcs.Proof.Proof.InclusionProof.GetRoot())

	kvStore := &contracts.Storage{}
	err = protobuf.Decode(v, kvStore)
	require.NoError(t, err)
	for _, kv := range kvStore.Store {
		fmt.Println(kv.Key)
		if kv.Key == "votes" {
			vs := &Votes{}
			err = protobuf.Decode(kv.Value, vs)
			require.NoError(t, err)
			for _, v := range vs.Votes {
				fmt.Println(v.Name, v.Choice)
			}
		} else if kv.Key == "header" {
			hdr := &core.ContractHeader{}
			err = protobuf.Decode(kv.Value, hdr)
			require.NoError(t, err)
			require.True(t, strings.Compare(hdr.CID.String(), cid.String()) == 0)
		}
	}

	time.Sleep(5 * time.Second)

	gcs, err = stateCl.Cl.GetState(cid)
	require.NoError(t, err)

	fmt.Println("After sleep:", gcs.Proof.Proof.InclusionProof.GetRoot())

	err = gcs.Proof.VerifyFromBlock(dfuRoster.ServicePublics(skipchain.ServiceName))
	require.NoError(t, err)

}

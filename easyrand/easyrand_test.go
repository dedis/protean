package easyrand

import (
	"flag"
	"strings"
	"testing"
	"time"

	cliutils "github.com/dedis/protean/client/utils"
	"github.com/dedis/protean/compiler"
	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

var uname string
var sname string
var rname string

func init() {
	flag.StringVar(&uname, "unit", "", "JSON file")
	flag.StringVar(&sname, "setup", "", "JSON file")
	flag.StringVar(&rname, "rand", "", "JSON file")
}

func initCompilerUnit(t *testing.T, local *onet.LocalTest, total int, roster *onet.Roster, hosts []*onet.Server, units []*sys.FunctionalUnit) {
	compServices := local.GetServices(hosts[:total], compiler.GetServiceID())
	compNodes := make([]*compiler.Service, len(compServices))
	for i := 0; i < len(compServices); i++ {
		compNodes[i] = compServices[i].(*compiler.Service)
	}
	root := compNodes[0]
	initReply, err := root.InitUnit(&compiler.InitUnitRequest{Roster: roster, ScCfg: &sys.ScConfig{MHeight: 2, BHeight: 2}})
	require.NoError(t, err)
	for _, n := range compNodes {
		_, err = n.StoreGenesis(&compiler.StoreGenesisRequest{Genesis: initReply.Genesis})
		require.NoError(t, err)
	}
	_, err = root.CreateUnits(&compiler.CreateUnitsRequest{Units: units})
	require.NoError(t, err)
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestRandom_Simple(t *testing.T) {
	total := 14
	compTotal := total / 2
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(total, true)
	defer local.CloseAll()
	compRoster := onet.NewRoster(roster.List[:compTotal])
	unitRoster := onet.NewRoster(roster.List[compTotal:])

	units, err := sys.PrepareUnits(unitRoster, &uname)
	require.Nil(t, err)

	initCompilerUnit(t, local, compTotal, compRoster, hosts[:compTotal], units)
	compCl := compiler.NewClient(compRoster)
	reply, err := compCl.GetDirectoryInfo()
	require.NoError(t, err)
	directory := reply.Directory

	randServices := local.GetServices(hosts[compTotal:], easyrandID)
	root := randServices[0].(*EasyRand)
	unitName := strings.Replace(ServiceName, "Service", "", 1)
	val := directory[unitName]
	txns := utils.ReverseMap(val.Txns)

	cfg := utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, unitName, txns)
	_, err = root.InitUnit(&InitUnitRequest{Cfg: cfg, Timeout: 5})
	require.Nil(t, err)

	// This part is done by the admin
	wf, err := cliutils.PrepareWorkflow(&sname, directory, nil, false)
	require.NoError(t, err)
	require.True(t, len(wf.Nodes) > 0)

	planReply, err := compCl.GenerateExecutionPlan(wf, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, planReply.ExecPlan.Publics)
	require.NotNil(t, planReply.Signature)

	////////
	randCl := NewClient(unitRoster)
	ed := &sys.ExecutionData{
		Index:       0,
		ExecPlan:    planReply.ExecPlan,
		ClientSigs:  nil,
		CompilerSig: planReply.Signature,
		UnitSigs:    make([]protocol.BlsSignature, len(planReply.ExecPlan.Workflow.Nodes)),
	}
	dkgReply, err := randCl.InitDKG(5, ed)
	require.NoError(t, err)
	require.NotNil(t, dkgReply.Public)
	ed.UnitSigs[ed.Index] = dkgReply.Sig
	ed.Index++

	////////
	time.Sleep(time.Second * 2)
	////////

	rWf, err := cliutils.PrepareWorkflow(&rname, directory, nil, false)
	require.NoError(t, err)
	require.True(t, len(rWf.Nodes) > 0)

	randPlan, err := compCl.GenerateExecutionPlan(rWf, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, randPlan.ExecPlan.Publics)
	require.NotNil(t, randPlan.Signature)

	randEd := &sys.ExecutionData{
		Index:       0,
		ExecPlan:    randPlan.ExecPlan,
		ClientSigs:  nil,
		CompilerSig: randPlan.Signature,
		UnitSigs:    make([]protocol.BlsSignature, len(planReply.ExecPlan.Workflow.Nodes)),
	}
	/// Advance rounds
	randCl.advanceRounds(t, randEd, 4)
	///////

	randReply, err := randCl.Randomness(randEd)
	require.NoError(t, err)
	require.NotNil(t, randReply.Value)
	randEd.UnitSigs[randEd.Index] = randReply.Sig
	randEd.Index++

	err = bls.Verify(suite, dkgReply.Public, randReply.Prev, randReply.Value)
	require.NoError(t, err)
	randCl.Close()
}

func (c *Client) advanceRounds(t *testing.T, ed *sys.ExecutionData, count int) {
	for i := 0; i < count; i++ {
		_, err := c.Randomness(ed)
		require.NoError(t, err)
	}
}

//func TestService(t *testing.T) {
//local := onet.NewTCPTest(cothority.Suite)
//hosts, roster, _ := local.GenTree(5, true)
//defer local.CloseAll()

//services := local.GetServices(hosts, serviceID)
//root := services[0].(*EasyRand)

//initReq := generateInitRequest(roster)
//_, err := root.InitUnit(initReq)
//dkgReply, err := root.InitDKG(&InitDKGRequest{Timeout: 5})
//require.NoError(t, err)

//// wait for DKG to finish on all
//time.Sleep(time.Second / 2)

//// round 0 (genesis)
//resp, err := root.Randomness(&RandomnessRequest{})
//require.NoError(t, err)
//require.NotNil(t, resp)
//require.NoError(t, bls.Verify(suite, dkgReply.Public, resp.Prev, resp.Value))

//// future rounds
//var resps []*RandomnessReply
//for i := 0; i < 3; i++ {
//prev := createNextMsg(root.blocks)
//resp, err := root.Randomness(&RandomnessRequest{})
//require.NoError(t, err)
//require.NotNil(t, resp)
//require.NoError(t, bls.Verify(suite, dkgReply.Public, prev, resp.Value))
//resps = append(resps, resp)
//}

//for _, resp := range resps {
//err := bls.Verify(suite, dkgReply.Public, resp.Prev, resp.Value)
//require.NoError(t, err)
//}

//}

//Timeout: 2,

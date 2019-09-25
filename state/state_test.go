package state

import (
	"flag"
	"strings"
	"testing"

	cliutils "github.com/dedis/protean/client/utils"
	"github.com/dedis/protean/compiler"
	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

var uname string
var wname string

func init() {
	flag.StringVar(&uname, "unit", "", "JSON file")
	flag.StringVar(&wname, "wflow", "", "JSON file")
}

type cs struct {
	total    int
	hosts    []*onet.Server
	roster   *onet.Roster
	services []onet.Service
	nodes    []*compiler.Service
	cl       *compiler.Client
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

func TestState_Simple(t *testing.T) {
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

	stServices := local.GetServices(hosts[compTotal:], stateID)
	root := stServices[0].(*Service)
	unitName := strings.Replace(ServiceName, "Service", "", 1)
	val := directory[unitName]
	txns := utils.ReverseMap(val.Txns)

	cfg := utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, unitName, txns)
	_, err = root.InitUnit(&InitUnitRequest{Cfg: cfg})
	require.Nil(t, err)

	// This part is done by the client
	wf, err := cliutils.PrepareWorkflow(&wname, directory, nil, false)
	require.NoError(t, err)
	require.True(t, len(wf.Nodes) > 0)

	planReply, err := compCl.GenerateExecutionPlan(wf, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, planReply.ExecPlan.Publics)
	require.NotNil(t, planReply.Signature)

	//ed := &sys.ExecutionData{
	//ExecPlan:    planReply.ExecPlan,
	//ClientSigs:  nil,
	//CompilerSig: planReply.Signature,
	//UnitSigs:    make([]protocol.BlsSignature, len(planReply.ExecPlan.Workflow.Nodes)),
	//}

	//idx := 0
	//stCl := NewClient(unitRoster)
	//ed.Index = idx
	//id := GenerateRandBytes()
	//dkgReply, err := thCl.InitDKG(id, ed)
	//require.Nil(t, err)
	//ed.UnitSigs[idx] = dkgReply.Sig
	//idx++

	//ed.Index = idx
	//mesgs, cts := GenerateMesgs(10, "Go Badgers!", dkgReply.X)
	//decReply, err := thCl.Decrypt(id, cts, true, ed)
	//require.NoError(t, err)
	//require.NotNil(t, decReply.Sig)
	//require.Nil(t, decReply.Partials)
	//for i, p := range decReply.Ps {
	//pt, err := p.Data()
	//require.Nil(t, err)
	//require.Equal(t, mesgs[i], pt)
	//}
	//ed.UnitSigs[idx] = decReply.Sig
	//idx++
}

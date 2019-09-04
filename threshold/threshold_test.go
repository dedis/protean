package threshold

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
	"go.dedis.ch/cothority/v3/blscosi/protocol"
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

func initCompilerUnit(t *testing.T, local *onet.LocalTest, total int, roster *onet.Roster, hosts []*onet.Server, units []*sys.FunctionalUnit) (*cs, map[string]*sys.UnitInfo) {
	compServices := local.GetServices(hosts[:total], compiler.GetServiceID())
	compNodes := make([]*compiler.Service, len(compServices))
	for i := 0; i < len(compServices); i++ {
		compNodes[i] = compServices[i].(*compiler.Service)
	}
	cl := compiler.NewClient()
	//root := compNodes[0]
	//initReply, err := root.InitUnit(&compiler.InitUnitRequest{Roster: roster, ScCfg: &sys.ScConfig{MHeight: 2, BHeight: 2}})
	initReply, err := cl.InitUnit(roster, &sys.ScConfig{MHeight: 2, BHeight: 2})
	require.NoError(t, err)
	//for _, n := range compNodes {
	for _, n := range hosts {
		//_, err = n.StoreGenesis(&compiler.StoreGenesisRequest{Genesis: initReply.Genesis})
		err := cl.StoreGenesis(n.ServerIdentity, initReply.Genesis)
		require.NoError(t, err)
	}
	//_, err = root.CreateUnits(&compiler.CreateUnitsRequest{Units: units})
	_, err = cl.CreateUnits(units)
	require.NoError(t, err)
	//reply, err := root.GetDirectoryInfo(&compiler.DirectoryInfoRequest{})
	reply, err := cl.GetDirectoryInfo()
	require.NoError(t, err)
	return &cs{total: total, hosts: hosts, roster: roster, services: compServices, nodes: compNodes, cl: cl}, reply.Directory
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestThreshold_Server(t *testing.T) {
	total := 14
	compTotal := total / 2
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(total, true)
	defer local.CloseAll()
	compRoster := onet.NewRoster(roster.List[:compTotal])
	unitRoster := onet.NewRoster(roster.List[compTotal:])

	units, err := sys.PrepareUnits(unitRoster, &uname)
	require.Nil(t, err)
	cs, directory := initCompilerUnit(t, local, compTotal, compRoster, hosts[:compTotal], units)
	require.NotNil(t, cs)
	require.NotNil(t, directory)

	thServices := local.GetServices(hosts[compTotal:], thresholdID)
	root := thServices[0].(*Service)
	unitName := strings.Replace(ServiceName, "Service", "", 1)
	val := directory[unitName]
	txns := utils.ReverseMap(val.Txns)

	initReq := GenerateInitRequest(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, unitName, txns)
	_, err = root.InitUnit(initReq)
	require.Nil(t, err)

	// This part is done by the client
	wf, err := cliutils.PrepareWorkflow(&wname, directory, nil, false)
	require.NoError(t, err)
	require.True(t, len(wf.Nodes) > 0)

	planReply, err := cs.cl.GenerateExecutionPlan(wf, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, planReply.ExecPlan.Publics)
	require.NotNil(t, planReply.Signature)

	ed := &sys.ExecutionData{
		ExecPlan:    planReply.ExecPlan,
		ClientSigs:  nil,
		CompilerSig: planReply.Signature,
		UnitSigs:    make([]protocol.BlsSignature, len(planReply.ExecPlan.Workflow.Nodes)),
	}

	//TODO: Change these to API calls
	id := NewDKGID(GenerateRandBytes())
	ed.Index = 0
	dkgReply, err := root.InitDKG(&InitDKGRequest{ID: id, ExecData: ed})
	require.Nil(t, err)
	mesgs, cts := GenerateMesgs(10, "Go Badgers!", dkgReply.X)
	ed.Index = 1
	ed.UnitSigs[0] = dkgReply.Sig
	decReply, err := root.Decrypt(&DecryptRequest{ID: id, Cs: cts, Server: true, ExecData: ed})
	require.Nil(t, decReply.Partials)
	require.Nil(t, err)
	for i, p := range decReply.Ps {
		pt, err := p.Data()
		require.Nil(t, err)
		require.Equal(t, mesgs[i], pt)
	}
}

//func TestThreshold_ServerFalse(t *testing.T) {
//n := 10
//local := onet.NewTCPTest(cothority.Suite)
//hosts, roster, _ := local.GenTree(n, true)
//defer local.CloseAll()

//services := local.GetServices(hosts, thresholdID)
//root := services[0].(*Service)
//initReq := GenerateInitRequest(roster)
//_, err := root.InitUnit(initReq)
//require.Nil(t, err)

//id := NewDKGID(GenerateRandBytes())
//dkgReply, err := root.InitDKG(&InitDKGRequest{ID: id})
//require.Nil(t, err)
//mesgs, cs := GenerateMesgs(10, "Go Badgers!", dkgReply.X)
//decReply, err := root.Decrypt(&DecryptRequest{ID: id, Cs: cs, Server: false})
//require.Nil(t, err)
//require.Nil(t, decReply.Ps)

//ps := RecoverMessages(n, cs, decReply.Partials)
//for i, p := range ps {
//pt, err := p.Data()
//require.Nil(t, err)
//require.Equal(t, mesgs[i], pt)
//}
//}

//func TestThreshold_Failures(t *testing.T) {
//n := 10
//local := onet.NewTCPTest(cothority.Suite)
//hosts, roster, _ := local.GenTree(n, true)
//defer local.CloseAll()

//services := local.GetServices(hosts, thresholdID)
//root := services[0].(*Service)
//initReq := GenerateInitRequest(roster)
//_, err := root.InitUnit(initReq)
//require.Nil(t, err)

//id := NewDKGID(GenerateRandBytes())
//fakeID := NewDKGID(GenerateRandBytes())
//dkgReply, err := root.InitDKG(&InitDKGRequest{ID: id})
//require.Nil(t, err)
//mesgs, cs := GenerateMesgs(10, "Go Badgers!", dkgReply.X)
//_, err = root.Decrypt(&DecryptRequest{ID: fakeID, Cs: cs, Server: true})
//require.Error(t, err)

//_, newCs := GenerateMesgs(10, "On Wisconsin!", dkgReply.X)
//decReply, err := root.Decrypt(&DecryptRequest{ID: id, Cs: newCs, Server: true})
//require.Nil(t, err)
//for i, p := range decReply.Ps {
//p, err := p.Data()
//require.Nil(t, err)
//require.True(t, !bytes.Equal(p, mesgs[i]))
//}
//}

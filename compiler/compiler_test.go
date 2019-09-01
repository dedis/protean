package compiler

import (
	"flag"
	"fmt"
	"testing"

	cliutils "github.com/dedis/protean/client/utils"
	"github.com/dedis/protean/sys"
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

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestCompiler_Basic(t *testing.T) {
	n := 7
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()
	services := local.GetServices(hosts, compilerID)
	root := services[0].(*Service)

	units, err := sys.PrepareUnits(roster, &uname)
	require.Nil(t, err)

	initReply, err := root.InitUnit(&InitUnitRequest{Roster: roster, ScCfg: &sys.ScConfig{MHeight: 2, BHeight: 2}})
	require.NoError(t, err)
	_, err = root.StoreGenesis(&StoreGenesisRequest{Genesis: initReply.Genesis})
	require.NoError(t, err)
	_, err = root.CreateUnits(&CreateUnitsRequest{Units: units})
	require.NoError(t, err)
	reply, err := root.GetDirectoryInfo(&DirectoryInfoRequest{})
	require.NoError(t, err)
	for k, v := range reply.Directory {
		fmt.Println("Unit name:", k)
		fmt.Println("Unit ID:", v.UnitID)
		fmt.Println(">> Transactions <<")
		for id, name := range v.Txns {
			fmt.Println(id, "--->", name)
		}
	}
}

func Test_PrepareWf(t *testing.T) {
	n := 7
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()
	services := local.GetServices(hosts, compilerID)
	root := services[0].(*Service)

	units, err := sys.PrepareUnits(roster, &uname)
	require.Nil(t, err)

	initReply, err := root.InitUnit(&InitUnitRequest{Roster: roster, ScCfg: &sys.ScConfig{MHeight: 2, BHeight: 2}})
	require.NoError(t, err)
	_, err = root.StoreGenesis(&StoreGenesisRequest{Genesis: initReply.Genesis})
	require.NoError(t, err)
	_, err = root.CreateUnits(&CreateUnitsRequest{Units: units})
	require.NoError(t, err)
	reply, err := root.GetDirectoryInfo(&DirectoryInfoRequest{})
	require.NoError(t, err)
	wf, err := cliutils.PrepareWorkflow(&wname, reply.Directory, nil, false)
	require.NoError(t, err)
	for _, w := range wf.Nodes {
		fmt.Println(w.UID, w.TID)
		fmt.Println("Deps:", w.Deps)
	}
}

func Test_GenerateEPNoAuth(t *testing.T) {
	n := 7
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()
	services := local.GetServices(hosts, compilerID)

	nodes := make([]*Service, len(services))
	for i := 0; i < len(services); i++ {
		nodes[i] = services[i].(*Service)
	}
	root := services[0].(*Service)

	units, err := sys.PrepareUnits(roster, &uname)
	require.Nil(t, err)

	initReply, err := root.InitUnit(&InitUnitRequest{Roster: roster, ScCfg: &sys.ScConfig{MHeight: 2, BHeight: 2}})
	require.NoError(t, err)
	for _, n := range nodes {
		_, err = n.StoreGenesis(&StoreGenesisRequest{Genesis: initReply.Genesis})
		require.NoError(t, err)
	}
	_, err = root.CreateUnits(&CreateUnitsRequest{Units: units})
	require.NoError(t, err)
	reply, err := root.GetDirectoryInfo(&DirectoryInfoRequest{})
	require.NoError(t, err)
	//fmt.Println(">>>>>>>>>>>>> DIRECTORY INFO <<<<<<<<<<<<<<<<")
	//for k, v := range reply.Directory {
	//fmt.Println("Unit name:", k, "--", "UID:", v.UnitID)
	//}
	wf, err := cliutils.PrepareWorkflow(&wname, reply.Directory, nil, false)
	//fmt.Println(">>>>>>>>>>>>> WORKFLOW INFO <<<<<<<<<<<<<<<")
	//for _, wfn := range wf.Nodes {
	//fmt.Println(wfn.UID, "with dependencies", wfn.Deps)
	//}
	require.NoError(t, err)
	require.Nil(t, wf.AuthPublics)
	planReply, err := root.GenerateExecutionPlan(&ExecutionPlanRequest{Workflow: wf, SigMap: nil})
	require.NoError(t, err)
	require.NotNil(t, planReply.ExecPlan.Publics)
	require.NotNil(t, planReply.Signature)
}

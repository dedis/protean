package compiler

import (
	"flag"
	"fmt"
	"testing"

	cliutils "github.com/dedis/protean/client/utils"
	"github.com/dedis/protean/sys"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
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
	wf, err := cliutils.PrepareWorkflow(&wname, reply.Directory, nil, false)
	require.NoError(t, err)
	require.Nil(t, wf.AuthPublics)
	planReply, err := root.GenerateExecutionPlan(&ExecutionPlanRequest{Workflow: wf, SigMap: nil})
	require.NoError(t, err)
	require.NotNil(t, planReply.ExecPlan.Publics)
	require.NotNil(t, planReply.Signature)
}

func Test_GenerateEPWithAuth_All(t *testing.T) {
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

	sz := 5
	rand := cothority.Suite.RandomStream()
	authPks := make([]kyber.Point, sz)
	authSks := make([]kyber.Scalar, sz)
	for i := 0; i < sz; i++ {
		h := cothority.Suite.Scalar().Pick(rand)
		authSks[i] = h
		authPks[i] = cothority.Suite.Point().Mul(h, nil)
	}

	wf, err := cliutils.PrepareWorkflow(&wname, reply.Directory, authPks, true)
	require.NoError(t, err)
	require.NotNil(t, wf.AuthPublics)

	sigMap, err := generateSigmap(wf, authPks, authSks)
	require.NoError(t, err)

	planReply, err := root.GenerateExecutionPlan(&ExecutionPlanRequest{Workflow: wf, SigMap: sigMap})
	require.NoError(t, err)
	require.NotNil(t, planReply.ExecPlan.Publics)
	require.NotNil(t, planReply.Signature)

}
func Test_GenerateEPWithAuth_NoAll(t *testing.T) {
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

	sz := 5
	rand := cothority.Suite.RandomStream()
	authPks := make([]kyber.Point, sz)
	authSks := make([]kyber.Scalar, sz)
	for i := 0; i < sz; i++ {
		h := cothority.Suite.Scalar().Pick(rand)
		authSks[i] = h
		authPks[i] = cothority.Suite.Point().Mul(h, nil)
	}

	wf, err := cliutils.PrepareWorkflow(&wname, reply.Directory, authPks, false)
	require.NoError(t, err)
	require.NotNil(t, wf.AuthPublics)

	for i := 0; i < sz; i++ {
		singleSm, err := generateSigmap(wf, authPks[i:i+1], authSks[i:i+1])
		require.NoError(t, err)
		planReply, err := root.GenerateExecutionPlan(&ExecutionPlanRequest{Workflow: wf, SigMap: singleSm})
		require.NoError(t, err)
		require.NotNil(t, planReply.ExecPlan.Publics)
		require.NotNil(t, planReply.Signature)
	}

}

func generateSigmap(wf *sys.Workflow, pks []kyber.Point, sks []kyber.Scalar) (map[string][]byte, error) {
	sm := make(map[string][]byte)
	for i := 0; i < len(sks); i++ {
		sig, err := SignWorkflow(wf, sks[i])
		if err != nil {
			return nil, err
		}
		key := pks[i].String()
		sm[key] = sig
	}
	return sm, nil
}

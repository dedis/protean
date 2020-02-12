package compiler

import (
	"fmt"
	"testing"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

var uname string
var wname string

func init() {
	//flag.StringVar(&uname, "unit", "", "JSON file")
	//flag.StringVar(&wname, "wflow", "", "JSON file")
	uname = "../units.json"
	wname = "./testdata/workflow.json"
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestBasic(t *testing.T) {
	n := 7
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, compilerID)
	nodes := make([]*Service, len(services))
	for i := 0; i < len(services); i++ {
		nodes[i] = services[i].(*Service)
	}
	//root := services[0].(*Service)
	root := nodes[0]
	fmt.Println(">>>>>> Root node is:", root.ServerIdentity(), "<<<<<<")

	units, err := sys.PrepareUnits(roster, &uname)
	require.Nil(t, err)
	initReply, err := root.InitUnit(&InitUnitRequest{Roster: roster, ScCfg: &sys.ScConfig{MHeight: 2, BHeight: 2}})
	require.NoError(t, err)
	for _, n := range nodes {
		_, err = n.StoreGenesis(&StoreGenesisRequest{Genesis: initReply.Genesis})
		require.NoError(t, err)
	}
	require.NoError(t, err)
	_, err = root.CreateUnits(&CreateUnitsRequest{Units: units})
	require.NoError(t, err)
	reply, err := root.GetDirectoryInfo(&DirectoryInfoRequest{})
	require.NoError(t, err)
	require.NotNil(t, reply)
}

func TestPrepareWf(t *testing.T) {
	n := 7
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, compilerID)
	nodes := make([]*Service, len(services))
	for i := 0; i < len(services); i++ {
		nodes[i] = services[i].(*Service)
	}
	//root := services[0].(*Service)
	root := nodes[0]
	fmt.Println(">>>>>> Root node is:", root.ServerIdentity(), "<<<<<<")

	units, err := sys.PrepareUnits(roster, &uname)
	require.Nil(t, err)

	initReply, err := root.InitUnit(&InitUnitRequest{Roster: roster, ScCfg: &sys.ScConfig{MHeight: 2, BHeight: 2}})
	require.NoError(t, err)
	for _, n := range nodes {
		_, err = n.StoreGenesis(&StoreGenesisRequest{Genesis: initReply.Genesis})
		require.NoError(t, err)
	}
	require.NoError(t, err)
	_, err = root.CreateUnits(&CreateUnitsRequest{Units: units})
	require.NoError(t, err)
	reply, err := root.GetDirectoryInfo(&DirectoryInfoRequest{})
	require.NoError(t, err)
	wf, err := PrepareWorkflow(&wname, reply.Directory)
	require.NoError(t, err)
	require.True(t, len(wf.Nodes) > 0)
}

func TestGenerateEP(t *testing.T) {
	n := 7
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, compilerID)
	nodes := make([]*Service, len(services))
	for i := 0; i < len(services); i++ {
		nodes[i] = services[i].(*Service)
	}

	root := nodes[0]
	fmt.Println(">>>>>> Root node is:", root.ServerIdentity(), "<<<<<<")

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
	wf, err := PrepareWorkflow(&wname, reply.Directory)
	require.NoError(t, err)
	planReply, err := root.GenerateExecutionPlan(&ExecutionPlanRequest{Workflow: wf})
	require.NoError(t, err)
	require.NotNil(t, planReply.ExecPlan.UnitPublics)
	require.NotNil(t, planReply.Signature)

	suite := pairing.NewSuiteBn256()
	epHash, err := utils.ComputeEPHash(planReply.ExecPlan)
	require.Nil(t, err)
	require.NoError(t, planReply.Signature.Verify(suite, epHash, roster.ServicePublics(ServiceName)))
}

//func Test_GenerateEPWithAuth_All(t *testing.T) {
//n := 7
//local := onet.NewTCPTest(cothority.Suite)
//hosts, roster, _ := local.GenTree(n, true)
//defer local.CloseAll()

//services := local.GetServices(hosts, compilerID)
//nodes := make([]*Service, len(services))
//for i := 0; i < len(services); i++ {
//nodes[i] = services[i].(*Service)
//}
////root := services[0].(*Service)
//root := nodes[0]
//fmt.Println(">>>>>> Root node is:", root.ServerIdentity(), "<<<<<<")

//units, err := sys.PrepareUnits(roster, &uname)
//require.Nil(t, err)

//initReply, err := root.InitUnit(&InitUnitRequest{Roster: roster, ScCfg: &sys.ScConfig{MHeight: 2, BHeight: 2}})
//require.NoError(t, err)
//for _, n := range nodes {
//_, err = n.StoreGenesis(&StoreGenesisRequest{Genesis: initReply.Genesis})
//require.NoError(t, err)
//}
//_, err = root.CreateUnits(&CreateUnitsRequest{Units: units})
//require.NoError(t, err)
//reply, err := root.GetDirectoryInfo(&DirectoryInfoRequest{})
//require.NoError(t, err)

//sz := 5
//rand := cothority.Suite.RandomStream()
//authPks := make([]kyber.Point, sz)
//authSks := make([]kyber.Scalar, sz)
//for i := 0; i < sz; i++ {
//h := cothority.Suite.Scalar().Pick(rand)
//authSks[i] = h
//authPks[i] = cothority.Suite.Point().Mul(h, nil)
//}

//wf, err := cliutils.PrepareWorkflow(&wname, reply.Directory, authPks, true)
//require.NoError(t, err)
//require.NotNil(t, wf.AuthPublics)

//sigMap, err := generateSigmap(wf, authPks, authSks)
//require.NoError(t, err)

//planReply, err := root.GenerateExecutionPlan(&ExecutionPlanRequest{Workflow: wf, SigMap: sigMap})
//require.NoError(t, err)
//require.NotNil(t, planReply.ExecPlan.UnitPublics)
//require.NotNil(t, planReply.Signature)

//suite := pairing.NewSuiteBn256()
//epHash, err := utils.ComputeEPHash(planReply.ExecPlan)
//require.Nil(t, err)
//require.NoError(t, planReply.Signature.Verify(suite, epHash, roster.ServicePublics(ServiceName)))

//}

//func Test_GenerateEPWithAuth_NoAll(t *testing.T) {
//n := 7
//local := onet.NewTCPTest(cothority.Suite)
//hosts, roster, _ := local.GenTree(n, true)
//defer local.CloseAll()

//services := local.GetServices(hosts, compilerID)
//nodes := make([]*Service, len(services))
//for i := 0; i < len(services); i++ {
//nodes[i] = services[i].(*Service)
//}
////root := services[0].(*Service)
//root := nodes[0]
//fmt.Println(">>>>>> Root node is:", root.ServerIdentity(), "<<<<<<")

//units, err := sys.PrepareUnits(roster, &uname)
//require.Nil(t, err)

//initReply, err := root.InitUnit(&InitUnitRequest{Roster: roster, ScCfg: &sys.ScConfig{MHeight: 2, BHeight: 2}})
//require.NoError(t, err)
//for _, n := range nodes {
//_, err = n.StoreGenesis(&StoreGenesisRequest{Genesis: initReply.Genesis})
//require.NoError(t, err)
//}
//_, err = root.CreateUnits(&CreateUnitsRequest{Units: units})
//require.NoError(t, err)
//reply, err := root.GetDirectoryInfo(&DirectoryInfoRequest{})
//require.NoError(t, err)

//sz := 5
//rand := cothority.Suite.RandomStream()
//authPks := make([]kyber.Point, sz)
//authSks := make([]kyber.Scalar, sz)
//for i := 0; i < sz; i++ {
//h := cothority.Suite.Scalar().Pick(rand)
//authSks[i] = h
//authPks[i] = cothority.Suite.Point().Mul(h, nil)
//}

//wf, err := cliutils.PrepareWorkflow(&wname, reply.Directory, authPks, false)
//require.NoError(t, err)
//require.NotNil(t, wf.AuthPublics)

//suite := pairing.NewSuiteBn256()
//for i := 0; i < sz; i++ {
//singleSm, err := generateSigmap(wf, authPks[i:i+1], authSks[i:i+1])
//require.NoError(t, err)
//planReply, err := root.GenerateExecutionPlan(&ExecutionPlanRequest{Workflow: wf, SigMap: singleSm})
//require.NoError(t, err)
//require.NotNil(t, planReply.ExecPlan.UnitPublics)
//require.NotNil(t, planReply.Signature)

//epHash, err := utils.ComputeEPHash(planReply.ExecPlan)
//require.Nil(t, err)
//require.NoError(t, planReply.Signature.Verify(suite, epHash, roster.ServicePublics(ServiceName)))
//}

//}

//func generateSigmap(wf *sys.Workflow, pks []kyber.Point, sks []kyber.Scalar) (map[string][]byte, error) {
//sm := make(map[string][]byte)
//for i := 0; i < len(sks); i++ {
////sig, err := SignWorkflow(wf, sks[i])
//sig, err := cliutils.SignWorkflow(wf, sks[i])
//if err != nil {
//return nil, err
//}
//key := pks[i].String()
//sm[key] = sig
//}
//return sm, nil
//}

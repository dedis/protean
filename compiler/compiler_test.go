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

	units, err := sys.PrepareUnits(roster, &uname)
	require.Nil(t, err)
	for _, u := range units {
		fmt.Println(u.Type, u.Name, u.Txns, u.NumNodes, u.Publics)
		fmt.Println("+++++")
	}

	services := local.GetServices(hosts, compilerID)
	root := services[0].(*Service)

	_, err = root.InitUnit(&InitUnitRequest{Roster: roster, ScData: &sys.ScInitData{MHeight: 2, BHeight: 2}})
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
	//for _, d := range reply.Data {
	//fmt.Println("Unit Name:", d.UnitName)
	//fmt.Println("Unit ID:", d.UnitID)
	//fmt.Println(">> Transactions <<")
	//for k, v := range d.Txns {
	//fmt.Println(k, "-->", v)
	//}
	//}
}

func Test_PrepareWf(t *testing.T) {
	n := 7
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()

	units, err := sys.PrepareUnits(roster, &uname)
	require.Nil(t, err)

	services := local.GetServices(hosts, compilerID)
	root := services[0].(*Service)

	_, err = root.InitUnit(&InitUnitRequest{Roster: roster, ScData: &sys.ScInitData{MHeight: 2, BHeight: 2}})
	require.NoError(t, err)
	_, err = root.CreateUnits(&CreateUnitsRequest{Units: units})
	require.NoError(t, err)
	reply, err := root.GetDirectoryInfo(&DirectoryInfoRequest{})
	require.NoError(t, err)
	wf, err := cliutils.PrepareWorkflow(&wname, reply.Directory)
	require.NoError(t, err)
	for _, w := range wf {
		fmt.Println(w.UID, w.TID)
		fmt.Println("Deps:", w.Deps)
	}
}

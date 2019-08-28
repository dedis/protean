package compiler

import (
	"flag"
	"fmt"
	"testing"

	"github.com/dedis/protean"
	"github.com/dedis/protean/sys"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

var fname string

func init() {
	flag.StringVar(&fname, "file", "", "JSON file")
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestCompiler_Basic(t *testing.T) {
	n := 7
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()

	units, err := sys.PrepareUnits(roster, &fname)
	require.Nil(t, err)
	for _, u := range units {
		fmt.Println(u.Type, u.Name, u.Txns, u.NumNodes, u.Publics)
		fmt.Println("+++++")
	}

	services := local.GetServices(hosts, compilerID)
	root := services[0].(*Service)

	_, err = root.InitUnit(&InitUnitRequest{Roster: roster, ScData: &protean.ScInitData{MHeight: 2, BHeight: 2}})
	require.NoError(t, err)
	_, err = root.CreateUnits(&CreateUnitsRequest{Units: units})
	require.NoError(t, err)
	reply, err := root.GetDirectoryData(&DirectoryDataRequest{})
	require.NoError(t, err)
	for _, d := range reply.Data {
		fmt.Println("Unit Name:", d.UnitName)
		fmt.Println("Unit ID:", d.UnitID)
		fmt.Println(">> Transactions <<")
		for k, v := range d.Txns {
			fmt.Println(k, "-->", v)
		}
	}
}

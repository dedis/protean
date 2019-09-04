package client

import (
	"flag"
	"testing"

	"github.com/dedis/protean/compiler"
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

type cs struct {
	total    int
	hosts    []*onet.Server
	roster   *onet.Roster
	services []onet.Service
	nodes    []*compiler.Service
}

func initCompilerUnit(t *testing.T, local *onet.LocalTest, total int, roster *onet.Roster, hosts []*onet.Server, units []*sys.FunctionalUnit) (*cs, map[string]*sys.UnitInfo) {
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
	require.NoError(t, err)
	_, err = root.CreateUnits(&compiler.CreateUnitsRequest{Units: units})
	require.NoError(t, err)
	reply, err := root.GetDirectoryInfo(&compiler.DirectoryInfoRequest{})
	require.NoError(t, err)
	return &cs{total: total, hosts: hosts, roster: roster, services: compServices, nodes: compNodes}, reply.Directory
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestClient_SimpleEP(t *testing.T) {
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
}

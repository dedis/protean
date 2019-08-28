package playground

import (
	"flag"
	"fmt"
	"testing"

	"github.com/dedis/protean/sys"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
)

var fname string

func init() {
	flag.StringVar(&fname, "file", "", "JSON file")
}

func TestSys(t *testing.T) {
	n := 7
	local := onet.NewTCPTest(cothority.Suite)
	_, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()

	units, err := sys.PrepareUnits(roster, &fname)
	require.Nil(t, err)
	for _, u := range units {
		fmt.Println(u.Type, u.Name, u.Txns, u.NumNodes, u.Publics)
		fmt.Println("=======")
	}
}

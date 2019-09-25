package easyneff

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestShuffle(t *testing.T) {
	n := 5
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, easyneffID)
	root := services[0].(*EasyNeff)
	// begin PROTEAN-related stuff
	initReq := GenerateInitRequest(roster)
	_, err := root.InitUnit(initReq)
	require.NoError(t, err)
	// end PROTEAN-related stuff

	req := GenerateRequest(10, []byte("abc"), nil)
	resp, err := root.Shuffle(&req)
	require.NoError(t, err)

	// verification should succeed
	require.Equal(t, n, len(resp.Proofs))
	require.NoError(t, resp.ShuffleVerify(req.G, req.H, req.Pairs, roster.Publics()))

	// if we change the order of the proofs and signatures then it should fail
	resp.Proofs = append(resp.Proofs[1:], resp.Proofs[0])
	sigs := append(roster.Publics()[1:], roster.Publics()[0])
	require.Error(t, resp.ShuffleVerify(req.G, req.H, req.Pairs, sigs))
}

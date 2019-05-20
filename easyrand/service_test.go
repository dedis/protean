package easyrand

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestService(t *testing.T) {
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, serviceID)
	root := services[0].(*EasyRand)
	_, err := root.InitDKG(&InitDKGReq{roster})
	require.NoError(t, err)

	// wait for DKG to finish on all
	time.Sleep(time.Second / 2)

	// round 0 (genesis)
	resp, err := root.Randomness(&RandomnessReq{roster})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, bls.Verify(suite, root.pubPoly.Commit(), []byte(genesisMsg), resp.Sig))

	// future rounds
	for i := 0; i < 3; i++ {
		prev := createNextMsg(root.blocks)
		resp, err := root.Randomness(&RandomnessReq{roster})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NoError(t, bls.Verify(suite, root.pubPoly.Commit(), prev, resp.Sig))
	}
}

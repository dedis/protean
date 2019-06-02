package easyneff

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestService(t *testing.T) {
	n := 5
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, serviceID)
	root := services[0].(*EasyNeff)
	req := generateReq(10, []byte("abc"))
	req.Roster = roster
	resp, err := root.Shuffle(&req)
	require.NoError(t, err)

	// verification should succeed
	require.Equal(t, n, len(resp.Proofs))
	require.NoError(t, resp.Verify(req.G, req.H, req.Pairs, roster.Publics()))

	// if we change the order of the proofs and signatures then it should fail
	resp.Proofs = append(resp.Proofs[1:], resp.Proofs[0])
	sigs := append(roster.Publics()[1:], roster.Publics()[0])
	require.Error(t, resp.Verify(req.G, req.H, req.Pairs, sigs))
}

func generateReq(n int, msg []byte) Request {
	r := random.New()
	pairs := make([]ElGamalPair, n)
	for i := range pairs {
		secret := cothority.Suite.Scalar().Pick(r)
		public := cothority.Suite.Point().Mul(secret, nil)
		c1, c2 := Encrypt(public, msg)
		pairs[i] = ElGamalPair{c1, c2}
	}

	return Request{
		Pairs: pairs,
		G:     cothority.Suite.Point().Base(),
		H:     cothority.Suite.Point().Pick(r),
	}
}

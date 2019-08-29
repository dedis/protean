package easyrand

import (
	"testing"
	"time"

	"github.com/dedis/protean/sys"
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

	initReq := generateInitRequest(roster)
	_, err := root.InitUnit(initReq)
	dkgReply, err := root.InitDKG(&InitDKGRequest{Timeout: 5})
	require.NoError(t, err)

	// wait for DKG to finish on all
	time.Sleep(time.Second / 2)

	// round 0 (genesis)
	resp, err := root.Randomness(&RandomnessRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	//require.NoError(t, bls.Verify(suite, root.pubPoly.Commit(), root.getRoundBlock(0), resp.Sig))
	//require.NoError(t, bls.Verify(suite, root.pubPoly.Commit(), resp.Prev, resp.Sig))
	require.NoError(t, bls.Verify(suite, dkgReply.Public, resp.Prev, resp.Sig))

	// future rounds
	var resps []*RandomnessReply
	for i := 0; i < 3; i++ {
		prev := createNextMsg(root.blocks)
		resp, err := root.Randomness(&RandomnessRequest{})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NoError(t, bls.Verify(suite, dkgReply.Public, prev, resp.Sig))
		resps = append(resps, resp)
	}

	for _, resp := range resps {
		//prev := root.getRoundBlock(resp.Round)
		//err := bls.Verify(suite, root.pubPoly.Commit(), prev, resp.Sig)
		err := bls.Verify(suite, dkgReply.Public, resp.Prev, resp.Sig)
		require.NoError(t, err)
	}

}

func generateInitRequest(roster *onet.Roster) *InitUnitRequest {
	//scData := &protean.ScInitData{
	scData := &sys.ScInitData{
		MHeight: 2,
		BHeight: 2,
	}
	//uData := &protean.BaseStorage{
	uData := &sys.BaseStorage{
		//UInfo: &protean.UnitInfo{
		UInfo: &sys.UnitInfo{
			UnitID:   "shuffle",
			UnitName: "shuffleUnit",
			Txns:     map[string]string{"a": "b", "c": "d"},
		},
	}
	return &InitUnitRequest{
		Roster:       roster,
		ScData:       scData,
		BaseStore:    uData,
		BlkInterval:  10,
		DurationType: time.Second,
		Timeout:      2,
	}
}

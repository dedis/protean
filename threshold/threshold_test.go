package threshold

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/dedis/protean"
	"github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestThreshold_Server(t *testing.T) {
	n := 10
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, thresholdID)
	root := services[0].(*Service)
	initReq := generateInitRequest(roster)
	_, err := root.InitUnit(initReq)
	require.Nil(t, err)

	id := hex.EncodeToString([]byte("thresh-test"))
	dkgReply, err := root.InitDKG(&InitDKGRequest{ID: id})
	require.Nil(t, err)
	mesgs, cs := generateMesgs(10, "Go Badgers!", dkgReply.X)
	decReply, err := root.Decrypt(&DecryptRequest{ID: id, Cs: cs, Server: true})
	require.Nil(t, decReply.Partials)
	require.Nil(t, err)

	for i, p := range decReply.Ps {
		pt, err := p.Data()
		require.Nil(t, err)
		require.Equal(t, mesgs[i], pt)
	}
}

func TestThreshold_ServerFalse(t *testing.T) {
	n := 10
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, thresholdID)
	root := services[0].(*Service)
	initReq := generateInitRequest(roster)
	_, err := root.InitUnit(initReq)
	require.Nil(t, err)

	id := hex.EncodeToString([]byte("thresh-test"))
	dkgReply, err := root.InitDKG(&InitDKGRequest{ID: id})
	require.Nil(t, err)
	mesgs, cs := generateMesgs(10, "Go Badgers!", dkgReply.X)
	decReply, err := root.Decrypt(&DecryptRequest{ID: id, Cs: cs, Server: false})
	require.Nil(t, err)
	require.Nil(t, decReply.Ps)

	ps := RecoverMessages(n, cs, decReply.Partials)
	for i, p := range ps {
		pt, err := p.Data()
		require.Nil(t, err)
		require.Equal(t, mesgs[i], pt)
	}
}

func TestThreshold_Failures(t *testing.T) {
	n := 10
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, thresholdID)
	root := services[0].(*Service)
	initReq := generateInitRequest(roster)
	_, err := root.InitUnit(initReq)
	require.Nil(t, err)

	id := hex.EncodeToString([]byte("thresh-test"))
	fakeID := hex.EncodeToString([]byte("threshtest"))
	dkgReply, err := root.InitDKG(&InitDKGRequest{ID: id})
	require.Nil(t, err)
	mesgs, cs := generateMesgs(10, "Go Badgers!", dkgReply.X)
	_, err = root.Decrypt(&DecryptRequest{ID: fakeID, Cs: cs, Server: true})
	require.Error(t, err)

	_, newCs := generateMesgs(10, "On Wisconsin!", dkgReply.X)
	decReply, err := root.Decrypt(&DecryptRequest{ID: id, Cs: newCs, Server: true})
	require.Nil(t, err)
	for i, p := range decReply.Ps {
		p, err := p.Data()
		require.Nil(t, err)
		require.True(t, !bytes.Equal(p, mesgs[i]))
	}
}

func generateMesgs(count int, m string, key kyber.Point) ([][]byte, []*utils.ElGamalPair) {
	mesgs := make([][]byte, count)
	cs := make([]*utils.ElGamalPair, count)
	for i := 0; i < count; i++ {
		s := fmt.Sprintf("%s%s%d%s", m, " -- ", i, "!")
		mesgs[i] = []byte(s)
		cs[i] = utils.ElGamalEncrypt(key, mesgs[i])
	}
	return mesgs, cs
}

func generateInitRequest(roster *onet.Roster) *InitUnitRequest {
	scData := &protean.ScInitData{
		MHeight: 2,
		BHeight: 2,
	}
	uData := &protean.BaseStorage{
		UInfo: &protean.UnitInfo{
			UnitID:   "threshold",
			UnitName: "thresholdUnit",
			Txns:     map[string]string{"a": "b", "c": "d"},
		},
	}
	return &InitUnitRequest{
		Roster:       roster,
		ScData:       scData,
		BaseStore:    uData,
		BlkInterval:  10,
		DurationType: time.Second,
	}
}

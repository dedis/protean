package threshold

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
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
	initReq := GenerateInitRequest(roster)
	_, err := root.InitUnit(initReq)
	require.Nil(t, err)

	id := NewDKGID(GenerateRandBytes())
	dkgReply, err := root.InitDKG(&InitDKGRequest{ID: id})
	require.Nil(t, err)
	mesgs, cs := GenerateMesgs(10, "Go Badgers!", dkgReply.X)
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
	initReq := GenerateInitRequest(roster)
	_, err := root.InitUnit(initReq)
	require.Nil(t, err)

	id := NewDKGID(GenerateRandBytes())
	dkgReply, err := root.InitDKG(&InitDKGRequest{ID: id})
	require.Nil(t, err)
	mesgs, cs := GenerateMesgs(10, "Go Badgers!", dkgReply.X)
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
	initReq := GenerateInitRequest(roster)
	_, err := root.InitUnit(initReq)
	require.Nil(t, err)

	id := NewDKGID(GenerateRandBytes())
	fakeID := NewDKGID(GenerateRandBytes())
	dkgReply, err := root.InitDKG(&InitDKGRequest{ID: id})
	require.Nil(t, err)
	mesgs, cs := GenerateMesgs(10, "Go Badgers!", dkgReply.X)
	_, err = root.Decrypt(&DecryptRequest{ID: fakeID, Cs: cs, Server: true})
	require.Error(t, err)

	_, newCs := GenerateMesgs(10, "On Wisconsin!", dkgReply.X)
	decReply, err := root.Decrypt(&DecryptRequest{ID: id, Cs: newCs, Server: true})
	require.Nil(t, err)
	for i, p := range decReply.Ps {
		p, err := p.Data()
		require.Nil(t, err)
		require.True(t, !bytes.Equal(p, mesgs[i]))
	}
}

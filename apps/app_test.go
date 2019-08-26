package apps

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/dedis/protean/easyneff"
	"github.com/dedis/protean/threshold"
	"github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestShuffleWithDKG(t *testing.T) {
	n := 7
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(n, true)
	defer local.CloseAll()

	neffSvcs := local.GetServices(hosts, easyneff.GetServiceID())
	threshSvcs := local.GetServices(hosts, threshold.GetServiceID())

	neffRoot := neffSvcs[0].(*easyneff.EasyNeff)
	initReq := easyneff.GenerateInitRequest(roster)
	_, err := neffRoot.InitUnit(initReq)
	require.NoError(t, err)

	threshRoot := threshSvcs[0].(*threshold.Service)
	initReq2 := threshold.GenerateInitRequest(roster)
	_, err = threshRoot.InitUnit(initReq2)
	require.NoError(t, err)

	id := threshold.NewDKGID(threshold.GenerateRandBytes())
	//dkgReply, err := threshRoot.InitDKG(&threshold.InitDKGRequest{ID: id})
	_, err = threshRoot.InitDKG(&threshold.InitDKGRequest{ID: id})
	require.NoError(t, err)

	req, sk, _ := easyneff.TestRequest(10, []byte("abc"))
	//req := easyneff.GenerateRequest(10, []byte("abc"), dkgReply.X)
	resp, err := neffRoot.Shuffle(&req)
	require.NoError(t, err)

	require.Equal(t, n, len(resp.Proofs))
	require.NoError(t, resp.ShuffleVerify(req.G, req.H, req.Pairs, roster.ServicePublics(easyneff.ServiceName)))

	pairs := resp.Proofs[n-1].Pairs
	for _, pair := range pairs {
		pt := utils.ElGamalDecrypt(sk, pair)
		text, _ := pt.Data()
		fmt.Println(bytes.Equal(text, []byte("abc")))
		//require.Nil(t, err)
		//require.Equal(t, text, []byte("abc"))
	}

	//tmpcs := resp.Proofs[n-1].Pairs
	//var cs []*utils.ElGamalPair
	//for _, p := range tmpcs {
	//cs = append(cs, &p)
	//}
	//decReply, err := threshRoot.Decrypt(&threshold.DecryptRequest{ID: id, Cs: cs, Server: true})
	//require.Nil(t, decReply.Partials)
	//require.Nil(t, err)

	//for _, p := range decReply.Ps {
	//pt, err := p.Data()
	//require.Nil(t, err)
	//require.Equal(t, []byte("abc"), pt)
	//}
}

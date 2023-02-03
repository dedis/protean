package threshold

import (
	"crypto/sha256"
	"fmt"
	"github.com/dedis/protean/threshold/utils"
	protean "github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"testing"
)

var uname string
var wname string

var testSuite = pairing.NewSuiteBn256()

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func Test_Threshold(t *testing.T) {
	total := 7
	threshold := total - (total-1)/3
	local := onet.NewTCPTest(cothority.Suite)
	_, roster, _ := local.GenTree(total, true)
	defer local.CloseAll()

	cl := NewClient(roster)
	_, err := cl.InitUnit()
	require.NoError(t, err)
	id := utils.GenerateRandBytes()
	dkgReply, err := cl.InitDKG(id)
	require.Nil(t, err)
	mesgs, cts := generateMesgs(10, "Go Badgers!", dkgReply.X)
	reply, err := cl.Decrypt(id, cts)
	require.NoError(t, err)
	require.NotNil(t, reply.Ps)
	require.NotNil(t, reply.Signature)

	h := sha256.New()
	for i, p := range reply.Ps {
		pt, err := p.Data()
		require.Nil(t, err)
		require.Equal(t, mesgs[i], pt)
		h.Write(pt)
	}
	hash := h.Sum(nil)
	publics := roster.ServicePublics(blscosi.ServiceName)
	require.NoError(t, reply.Signature.VerifyWithPolicy(testSuite, hash,
		publics, sign.NewThresholdPolicy(threshold)))
}

func generateMesgs(count int, m string, key kyber.Point) ([][]byte, []protean.ElGamalPair) {
	mesgs := make([][]byte, count)
	cs := make([]protean.ElGamalPair, count)
	for i := 0; i < count; i++ {
		s := fmt.Sprintf("%s%s%d%s", m, " -- ", i, "!")
		mesgs[i] = []byte(s)
		c := protean.ElGamalEncrypt(key, mesgs[i])
		cs[i] = c
	}
	return mesgs, cs
}

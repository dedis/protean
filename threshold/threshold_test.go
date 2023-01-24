package threshold

import (
	"crypto/sha256"
	"fmt"
	"github.com/dedis/protean/utils"
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

func init() {
	uname = "../units.json"
	wname = "./testdata/wflow.json"
	//flag.StringVar(&uname, "unit", "", "JSON file")
	//flag.StringVar(&wname, "wflow", "", "JSON file")
}

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
	id := GenerateRandBytes()
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

//func Test_Server(t *testing.T) {
//	total := 14
//	compTotal := total / 2
//	local := onet.NewTCPTest(cothority.Suite)
//	hosts, roster, _ := local.GenTree(total, true)
//	defer local.CloseAll()
//	compRoster := onet.NewRoster(roster.List[:compTotal])
//	unitRoster := onet.NewRoster(roster.List[compTotal:])
//	units, err := sys.PrepareUnits(unitRoster, &uname)
//	require.Nil(t, err)
//
//	err = libtest.InitCompilerUnit(local, compTotal, compRoster, hosts[:compTotal], units)
//	require.NoError(t, err)
//	compCl := compiler.NewClient(compRoster)
//	reply, err := compCl.GetDirectoryInfo()
//	require.NoError(t, err)
//	directory := reply.Directory
//
//	thServices := local.GetServices(hosts[compTotal:], thresholdID)
//	root := thServices[0].(*Service)
//	unitName := strings.Replace(ServiceName, "Service", "", 1)
//	val := directory[unitName]
//	txns := utils.ReverseMap(val.Txns)
//
//	cfg := utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, unitName, txns, 10)
//	_, err = root.InitUnit(&InitUnitRequest{Cfg: cfg})
//	require.Nil(t, err)
//
//	// This part is done by the client
//	wf, err := compiler.PrepareWorkflow(&wname, directory)
//	require.NoError(t, err)
//	require.True(t, len(wf.Nodes) > 0)
//
//	planReply, err := compCl.CreateExecutionPlan(wf)
//	require.NoError(t, err)
//	require.NotNil(t, planReply.ExecPlan.UnitPublics)
//	require.NotNil(t, planReply.Signature)
//	ed := compiler.PrepareExecutionData(planReply)
//
//	thCl := NewClient(unitRoster)
//	id := GenerateRandBytes()
//	dkgReply, err := thCl.InitDKG(id, ed)
//	require.Nil(t, err)
//	ed.UnitSigs[ed.Index] = dkgReply.Sig
//	ed.Index++
//
//	mesgs, cts := generateMesgs(10, "Go Badgers!", dkgReply.X)
//	decReply, err := thCl.Decrypt(id, cts, true, ed)
//	require.NoError(t, err)
//	require.NotNil(t, decReply.Sig)
//	require.Nil(t, decReply.partials)
//	for i, p := range decReply.Ps {
//		pt, err := p.Data()
//		require.Nil(t, err)
//		require.Equal(t, mesgs[i], pt)
//		fmt.Println("Mesg", i, "is", string(pt))
//	}
//	ed.UnitSigs[ed.Index] = decReply.Sig
//	ed.Index++
//}

//func Test_ServerFalse(t *testing.T) {
//	total := 14
//	compTotal := total / 2
//	local := onet.NewTCPTest(cothority.Suite)
//	hosts, roster, _ := local.GenTree(total, true)
//	defer local.CloseAll()
//	compRoster := onet.NewRoster(roster.List[:compTotal])
//	unitRoster := onet.NewRoster(roster.List[compTotal:])
//	units, err := sys.PrepareUnits(unitRoster, &uname)
//	require.Nil(t, err)
//
//	err = libtest.InitCompilerUnit(local, compTotal, compRoster, hosts[:compTotal], units)
//	require.NoError(t, err)
//	compCl := compiler.NewClient(compRoster)
//	reply, err := compCl.GetDirectoryInfo()
//	require.NoError(t, err)
//	directory := reply.Directory
//
//	thServices := local.GetServices(hosts[compTotal:], thresholdID)
//	root := thServices[0].(*Service)
//	unitName := strings.Replace(ServiceName, "Service", "", 1)
//	val := directory[unitName]
//	txns := utils.ReverseMap(val.Txns)
//
//	cfg := utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, unitName, txns, 10)
//	_, err = root.InitUnit(&InitUnitRequest{Cfg: cfg})
//	require.Nil(t, err)
//
//	// This part is done by the client
//	wf, err := compiler.PrepareWorkflow(&wname, directory)
//	require.NoError(t, err)
//	require.True(t, len(wf.Nodes) > 0)
//
//	planReply, err := compCl.CreateExecutionPlan(wf)
//	require.NoError(t, err)
//	require.NotNil(t, planReply.ExecPlan.UnitPublics)
//	require.NotNil(t, planReply.Signature)
//	ed := compiler.PrepareExecutionData(planReply)
//
//	thCl := NewClient(unitRoster)
//	id := GenerateRandBytes()
//	dkgReply, err := thCl.InitDKG(id, ed)
//	require.Nil(t, err)
//	ed.UnitSigs[ed.Index] = dkgReply.Sig
//	ed.Index++
//
//	_, cts := generateMesgs(10, "Go Badgers!", dkgReply.X)
//	decReply, err := thCl.Decrypt(id, cts, false, ed)
//	require.NoError(t, err)
//	require.NotNil(t, decReply.Sig)
//	require.Nil(t, decReply.Ps)
//
//	ps := RecoverMessages(len(unitRoster.List), cts, decReply.partials)
//	for i, p := range ps {
//		pt, err := p.Data()
//		require.NoError(t, err)
//		require.Equal(t, mesgs[i], pt)
//		fmt.Println("Recovered message is:", pt)
//	}
//}

//func TestThreshold_Failures(t *testing.T) {
//n := 10
//local := onet.NewTCPTest(cothority.Suite)
//hosts, roster, _ := local.GenTree(n, true)
//defer local.CloseAll()

//services := local.GetServices(hosts, thresholdID)
//root := services[0].(*Service)
//initReq := GenerateInitRequest(roster)
//_, err := root.InitUnit(initReq)
//require.Nil(t, err)

//id := NewDKGID(GenerateRandBytes())
//fakeID := NewDKGID(GenerateRandBytes())
//dkgReply, err := root.InitDKG(&InitDKGRequest{ID: id})
//require.Nil(t, err)
//mesgs, cs := GenerateMesgs(10, "Go Badgers!", dkgReply.X)
//_, err = root.Decrypt(&DecryptRequest{ID: fakeID, Cs: cs, Server: true})
//require.Error(t, err)

//_, newCs := GenerateMesgs(10, "On Wisconsin!", dkgReply.X)
//decReply, err := root.Decrypt(&DecryptRequest{ID: id, Cs: newCs, Server: true})
//require.Nil(t, err)
//for i, p := range decReply.Ps {
//p, err := p.Store()
//require.Nil(t, err)
//require.True(t, !bytes.Equal(p, mesgs[i]))
//}
//}

func generateMesgs(count int, m string, key kyber.Point) ([][]byte, []utils.ElGamalPair) {
	mesgs := make([][]byte, count)
	cs := make([]utils.ElGamalPair, count)
	for i := 0; i < count; i++ {
		s := fmt.Sprintf("%s%s%d%s", m, " -- ", i, "!")
		mesgs[i] = []byte(s)
		c := utils.ElGamalEncrypt(key, mesgs[i])
		cs[i] = c
	}
	return mesgs, cs
}

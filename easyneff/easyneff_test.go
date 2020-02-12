package easyneff

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dedis/protean/compiler"
	"github.com/dedis/protean/libtest"
	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/threshold"
	"github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

var uname string
var wname string

func init() {
	//flag.StringVar(&uname, "unit", "", "JSON file")
	//flag.StringVar(&wname, "wflow", "", "JSON file")
	uname = "../units.json"
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestDKG(t *testing.T) {
	wname = "./testdata/withdkg.json"
	total := 14
	compTotal := total / 2
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(total, true)
	defer local.CloseAll()
	compRoster := onet.NewRoster(roster.List[:compTotal])
	unitRoster := onet.NewRoster(roster.List[compTotal:])

	units, err := sys.PrepareUnits(unitRoster, &uname)
	require.Nil(t, err)

	err = libtest.InitCompilerUnit(local, compTotal, compRoster, hosts[:compTotal], units)
	require.NoError(t, err)

	compCl := compiler.NewClient(compRoster)
	reply, err := compCl.GetDirectoryInfo()
	require.NoError(t, err)
	directory := reply.Directory

	neffServices := local.GetServices(hosts[compTotal:], easyneffID)
	root := neffServices[0].(*EasyNeff)
	unitName := strings.Replace(ServiceName, "Service", "", 1)
	val := directory[unitName]
	txns := utils.ReverseMap(val.Txns)
	cfg := utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, unitName, txns, 10)
	_, err = root.InitUnit(&InitUnitRequest{Cfg: cfg})
	require.Nil(t, err)

	////////////

	thName := strings.Replace(threshold.ServiceName, "Service", "", 1)
	val = directory[thName]
	thTxns := utils.ReverseMap(val.Txns)
	cfg = utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, thName, thTxns, 10)

	thCl := threshold.NewClient(unitRoster)
	_, err = thCl.InitUnit(cfg)
	require.NoError(t, err)

	///////////

	wf, err := compiler.PrepareWorkflow(&wname, directory)
	require.NoError(t, err)
	require.True(t, len(wf.Nodes) > 0)

	planReply, err := compCl.GenerateExecutionPlan(wf)
	require.NoError(t, err)
	require.NotNil(t, planReply.ExecPlan.UnitPublics)
	require.NotNil(t, planReply.Signature)
	ed := compiler.PrepareExecutionData(planReply)

	///////////

	id := threshold.GenerateRandBytes()
	dkgReply, err := thCl.InitDKG(id, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = dkgReply.Sig
	ed.Index++

	///////////

	req, _ := generateRequest(10, []byte("On Wisconsin!"), dkgReply.X, ed)
	resp, err := root.Shuffle(&req)
	require.NoError(t, err)
	//// verification should succeed
	n := len(unitRoster.List)
	require.Equal(t, n, len(resp.Proofs))
	require.NoError(t, resp.ShuffleVerify(req.G, req.H, req.Pairs, unitRoster.Publics()))
	ed.UnitSigs[ed.Index] = resp.Sig
	ed.Index++

	///////////

	var pairs []*utils.ElGamalPair
	cs := resp.Proofs[n-1].Pairs
	for _, p := range cs {
		pairs = append(pairs, &p)
	}
	decReply, err := thCl.Decrypt(id, pairs, true, ed)
	require.NoError(t, err)

	for _, p := range decReply.Ps {
		pt, err := p.Data()
		fmt.Println(string(pt))
		require.NoError(t, err)
	}

}

func TestDecrypt(t *testing.T) {
	wname = "./testdata/wflow.json"
	total := 14
	compTotal := total / 2
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(total, true)
	defer local.CloseAll()
	compRoster := onet.NewRoster(roster.List[:compTotal])
	unitRoster := onet.NewRoster(roster.List[compTotal:])

	units, err := sys.PrepareUnits(unitRoster, &uname)
	require.Nil(t, err)

	err = libtest.InitCompilerUnit(local, compTotal, compRoster, hosts[:compTotal], units)
	require.NoError(t, err)

	compCl := compiler.NewClient(compRoster)
	reply, err := compCl.GetDirectoryInfo()
	require.NoError(t, err)
	directory := reply.Directory

	neffServices := local.GetServices(hosts[compTotal:], easyneffID)
	root := neffServices[0].(*EasyNeff)
	unitName := strings.Replace(ServiceName, "Service", "", 1)
	val := directory[unitName]
	txns := utils.ReverseMap(val.Txns)
	cfg := utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, unitName, txns, 10)
	_, err = root.InitUnit(&InitUnitRequest{Cfg: cfg})
	require.Nil(t, err)

	////////////

	wf, err := compiler.PrepareWorkflow(&wname, directory)
	require.NoError(t, err)
	require.True(t, len(wf.Nodes) > 0)

	planReply, err := compCl.GenerateExecutionPlan(wf)
	require.NoError(t, err)
	require.NotNil(t, planReply.ExecPlan.UnitPublics)
	require.NotNil(t, planReply.Signature)
	ed := compiler.PrepareExecutionData(planReply)

	///////////

	req, sks := generateRequest(10, []byte("On Wisconsin!"), nil, ed)
	resp, err := root.Shuffle(&req)
	require.NoError(t, err)
	//// verification should succeed
	n := len(unitRoster.List)
	require.Equal(t, n, len(resp.Proofs))
	require.NoError(t, resp.ShuffleVerify(req.G, req.H, req.Pairs, unitRoster.Publics()))
	ed.UnitSigs[ed.Index] = resp.Sig
	ed.Index++

	///////////

	cs := resp.Proofs[n-1].Pairs
	for i, p := range cs {
		pt := utils.ElGamalDecrypt(sks[i], p)
		data, err := pt.Data()
		require.NoError(t, err)
		fmt.Println(data)
	}
}

func TestSimple(t *testing.T) {
	wname = "./testdata/wflow.json"
	total := 14
	compTotal := total / 2
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(total, true)
	defer local.CloseAll()
	compRoster := onet.NewRoster(roster.List[:compTotal])
	unitRoster := onet.NewRoster(roster.List[compTotal:])

	units, err := sys.PrepareUnits(unitRoster, &uname)
	require.Nil(t, err)

	err = libtest.InitCompilerUnit(local, compTotal, compRoster, hosts[:compTotal], units)
	require.NoError(t, err)
	compCl := compiler.NewClient(compRoster)
	reply, err := compCl.GetDirectoryInfo()
	require.NoError(t, err)
	directory := reply.Directory

	neffServices := local.GetServices(hosts[compTotal:], easyneffID)
	root := neffServices[0].(*EasyNeff)
	unitName := strings.Replace(ServiceName, "Service", "", 1)
	val := directory[unitName]
	txns := utils.ReverseMap(val.Txns)

	cfg := utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, unitName, txns, 10)
	_, err = root.InitUnit(&InitUnitRequest{Cfg: cfg})
	require.Nil(t, err)

	wf, err := compiler.PrepareWorkflow(&wname, directory)
	require.NoError(t, err)
	require.True(t, len(wf.Nodes) > 0)

	planReply, err := compCl.GenerateExecutionPlan(wf)
	require.NoError(t, err)
	require.NotNil(t, planReply.ExecPlan.UnitPublics)
	require.NotNil(t, planReply.Signature)

	ed := compiler.PrepareExecutionData(planReply)

	req, _ := generateRequest(10, []byte("abc"), nil, ed)
	resp, err := root.Shuffle(&req)
	require.NoError(t, err)

	//// verification should succeed
	require.Equal(t, len(unitRoster.List), len(resp.Proofs))
	require.NoError(t, resp.ShuffleVerify(req.G, req.H, req.Pairs, unitRoster.Publics()))

	//// if we change the order of the proofs and signatures then it should fail
	resp.Proofs = append(resp.Proofs[1:], resp.Proofs[0])
	sigs := append(roster.Publics()[1:], roster.Publics()[0])
	require.Error(t, resp.ShuffleVerify(req.G, req.H, req.Pairs, sigs))
}

func generateRequest(n int, msg []byte, key kyber.Point, ed *sys.ExecutionData) (ShuffleRequest, []kyber.Scalar) {
	var public kyber.Point
	r := random.New()
	pairs := make([]utils.ElGamalPair, n)
	sks := make([]kyber.Scalar, n)
	for i := range pairs {
		if key != nil {
			public = key
		} else {
			secret := cothority.Suite.Scalar().Pick(r)
			public = cothority.Suite.Point().Mul(secret, nil)
			sks[i] = secret
		}
		c := utils.ElGamalEncrypt(public, msg)
		pairs[i] = utils.ElGamalPair{K: c.K, C: c.C}
	}

	return ShuffleRequest{
		Pairs:    pairs,
		G:        cothority.Suite.Point().Base(),
		H:        cothority.Suite.Point().Pick(r),
		ExecData: ed,
	}, sks
}

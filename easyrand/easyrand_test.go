package easyrand

import (
	"fmt"
	"github.com/dedis/protean/easyrand/protocol"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"testing"
)

var testSuite = pairing.NewSuiteBn256()

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func Test_Simple(t *testing.T) {
	total := 10
	threshold := total - (total-1)/3
	local := onet.NewTCPTest(cothority.Suite)
	_, roster, _ := local.GenTree(total, true)
	defer local.CloseAll()

	cl := NewClient(roster)
	_, err := cl.InitUnit()
	require.NoError(t, err)
	_, err = cl.InitDKG()
	require.NoError(t, err)

	// Dummy call
	cl.Randomness(0)
	cl.Randomness(1)
	cl.Randomness(2)
	randReply, err := cl.Randomness(3)
	require.NoError(t, err)
	require.NotNil(t, randReply.Value)
	fmt.Println(randReply.Round)

	rv := protocol.RandomnessVerify{Data: &protocol.Data{Public: randReply.
		Public, Round: randReply.Round, Prev: randReply.Prev, Value: randReply.Value}}
	hash, err := rv.CalculateHash()
	require.NoError(t, err)
	publics := roster.ServicePublics(blscosi.ServiceName)
	// Check the collective signature on the randomness output
	require.NoError(t, randReply.Signature.VerifyWithPolicy(testSuite, hash,
		publics, sign.NewThresholdPolicy(threshold)))

	// Check the signature on the randomness value (DKG)
	err = bls.Verify(suite, randReply.Public, randReply.Prev, randReply.Value)
	require.NoError(t, err)
}

//func Test_Simple(t *testing.T) {
//	sname = "./testdata/setup.json"
//	rname = "./testdata/rand.json"
//	total := 14
//	compTotal := total / 2
//	local := onet.NewTCPTest(cothority.Suite)
//	hosts, roster, _ := local.GenTree(total, true)
//	defer local.CloseAll()
//	compRoster := onet.NewRoster(roster.List[:compTotal])
//	unitRoster := onet.NewRoster(roster.List[compTotal:])
//
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
//	randServices := local.GetServices(hosts[compTotal:], easyrandID)
//	root := randServices[0].(*EasyRand)
//	unitName := strings.Replace(ServiceName, "Service", "", 1)
//	val := directory[unitName]
//	txns := utils.ReverseMap(val.Txns)
//
//	cfg := utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, unitName, txns, 10)
//	_, err = root.InitUnit(&InitUnitRequest{Cfg: cfg, Timeout: 5})
//	require.Nil(t, err)
//
//	// This part is done by the admin
//	wf, err := compiler.PrepareWorkflow(&sname, directory)
//	require.NoError(t, err)
//	require.True(t, len(wf.Nodes) > 0)
//
//	planReply, err := compCl.CreateExecutionPlan(wf)
//	require.NoError(t, err)
//	require.NotNil(t, planReply.ExecPlan.UnitPublics)
//	require.NotNil(t, planReply.Signature)
//
//	////////
//	randCl := NewClient(unitRoster)
//	ed := compiler.PrepareExecutionData(planReply)
//	dkgReply, err := randCl.InitDKG(5, ed)
//	require.NoError(t, err)
//	require.NotNil(t, dkgReply.Public)
//	ed.UnitSigs[ed.Index] = dkgReply.Sig
//	ed.Index++
//
//	////////
//	time.Sleep(time.Second * 2)
//	////////
//
//	rWf, err := compiler.PrepareWorkflow(&rname, directory)
//	require.NoError(t, err)
//	require.True(t, len(rWf.Nodes) > 0)
//
//	randPlan, err := compCl.CreateExecutionPlan(rWf)
//	require.NoError(t, err)
//	require.NotNil(t, randPlan.ExecPlan.UnitPublics)
//	require.NotNil(t, randPlan.Signature)
//
//	randEd := compiler.PrepareExecutionData(randPlan)
//	/// Advance rounds
//	randCl.advanceRounds(t, randEd, 4)
//	///////
//
//	randReply, err := randCl.Randomness(randEd)
//	require.NoError(t, err)
//	require.NotNil(t, randReply.Value)
//	randEd.UnitSigs[randEd.Index] = randReply.Sig
//	randEd.Index++
//
//	err = bls.Verify(suite, dkgReply.Public, randReply.Prev, randReply.Value)
//	require.NoError(t, err)
//	randCl.Close()
//	//log.Info("Round number is:", randReply.Round)
//}

//func (c *Client) advanceRounds(t *testing.T, ed *sys.ExecutionData, count int) {
//	for i := 0; i < count; i++ {
//		_, err := c.Randomness()
//		require.NoError(t, err)
//	}
//}

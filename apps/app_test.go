package apps

import (
	"flag"
	"fmt"
	"strings"
	"testing"

	cliutils "github.com/dedis/protean/client/utils"
	"github.com/dedis/protean/compiler"
	"github.com/dedis/protean/pristore"
	"github.com/dedis/protean/state"
	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

var uname string
var sname string

//var wname string
//var rname string

func init() {
	flag.StringVar(&uname, "unit", "", "JSON file")
	flag.StringVar(&sname, "setup", "", "JSON file")
	//flag.StringVar(&wname, "write", "", "JSON file")
	//flag.StringVar(&rname, "read", "", "JSON file")
}

func initCompilerUnit(t *testing.T, local *onet.LocalTest, total int, roster *onet.Roster, hosts []*onet.Server, units []*sys.FunctionalUnit) {
	compServices := local.GetServices(hosts[:total], compiler.GetServiceID())
	compNodes := make([]*compiler.Service, len(compServices))
	for i := 0; i < len(compServices); i++ {
		compNodes[i] = compServices[i].(*compiler.Service)
	}
	root := compNodes[0]
	initReply, err := root.InitUnit(&compiler.InitUnitRequest{Roster: roster, ScCfg: &sys.ScConfig{MHeight: 2, BHeight: 2}})
	require.NoError(t, err)
	for _, n := range compNodes {
		_, err = n.StoreGenesis(&compiler.StoreGenesisRequest{Genesis: initReply.Genesis})
		require.NoError(t, err)
	}
	_, err = root.CreateUnits(&compiler.CreateUnitsRequest{Units: units})
	require.NoError(t, err)
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func Test_CalypsoLottery_Simple(t *testing.T) {
	total := 14
	unitCnt := total / 2
	local := onet.NewTCPTest(cothority.Suite)
	hosts, roster, _ := local.GenTree(total, true)
	defer local.CloseAll()
	compRoster := onet.NewRoster(roster.List[:unitCnt])
	unitRoster := onet.NewRoster(roster.List[unitCnt : unitCnt*2])

	units, err := sys.PrepareUnits(unitRoster, &uname)
	require.NoError(t, err)

	initCompilerUnit(t, local, unitCnt, compRoster, hosts[:unitCnt], units)
	compCl := compiler.NewClient(compRoster)
	reply, err := compCl.GetDirectoryInfo()
	require.NoError(t, err)
	directory := reply.Directory

	// BEGIN INITIALIZE UNITS
	// PRIVATE STORAGE UNIT
	psID := pristore.GetServiceID()
	psSvcs := local.GetServices(hosts[unitCnt:unitCnt*2], psID)
	psRoot := psSvcs[0].(*pristore.Service)
	psName := strings.Replace(pristore.ServiceName, "Service", "", 1)
	val := directory[psName]
	psTxns := utils.ReverseMap(val.Txns)

	cfg := utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, psName, psTxns)
	initReply, err := psRoot.InitUnit(&pristore.InitUnitRequest{Cfg: cfg})
	require.NoError(t, err)
	for _, svc := range psSvcs {
		who := svc.(*pristore.Service)
		_, err := who.Authorize(&pristore.AuthorizeRequest{Request: &calypso.Authorise{ByzCoinID: initReply.ID}})
		require.NoError(t, err)
	}

	// STATE UNIT
	stID := state.GetServiceID()
	stSvcs := local.GetServices(hosts[unitCnt:unitCnt*2], stID)
	stRoot := stSvcs[0].(*state.Service)
	stName := strings.Replace(state.ServiceName, "Service", "", 1)
	val = directory[stName]
	stTxns := utils.ReverseMap(val.Txns)
	cfg = utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, stName, stTxns)
	_, err = stRoot.InitUnit(&state.InitUnitRequest{Cfg: cfg})
	require.NoError(t, err)
	// END INITIALIZE UNITS

	// BEGIN SETUP WORKFLOW (LOTTERY ORGANIZER)
	setupWf, err := cliutils.PrepareWorkflow(&sname, directory, nil, false)
	require.NoError(t, err)
	planReply, err := compCl.GenerateExecutionPlan(setupWf, nil, nil)
	require.NoError(t, err)
	ed := cliutils.PrepareExecutionData(planReply, nil)

	psCl := pristore.NewClient(unitRoster)
	ltsReply, err := psCl.CreateLTS(unitRoster, 2, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = ltsReply.Sig
	ed.Index++
	fmt.Println("Shared key:", ltsReply.Reply.X.String())
	fmt.Println("IID:", ltsReply.Reply.InstanceID)

	writers := generateWriters(2)
	readers := generateReaders(1)
	lotDarc := pristore.CreateDarc(readers[0].Identity(), "lotterydarc")
	err = pristore.AddWriteRule(lotDarc, writers...)
	require.NoError(t, err)
	err = pristore.AddReadRule(lotDarc, readers...)
	require.NoError(t, err)
	sdReply, err := psCl.SpawnDarc(*lotDarc, 2, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = sdReply.Sig
	ed.Index++
	psCl.Close()

	organizer := readers[0]
	writerIDs := make([]string, len(writers))
	for i, w := range writers {
		writerIDs[i] = w.Identity().String()
	}
	stCl := state.NewClient(unitRoster)
	orgDarc := darc.NewDarc(darc.InitRules([]darc.Identity{organizer.Identity()}, []darc.Identity{organizer.Identity()}), []byte("organizer"))
	orgDarc.Rules.AddRule(darc.Action("spawn:"+state.ContractCalyLotteryID), expression.InitOrExpr(organizer.Identity().String()))
	orgDarc.Rules.AddRule(darc.Action("invoke:"+state.ContractCalyLotteryID+".storeticket"), expression.InitOrExpr(writerIDs...))
	sd, err := stCl.SpawnDarc(*orgDarc, 3, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = sd.Sig
	ed.Index++
	args, err := prepareSpawnArgs(ltsReply, writers)
	require.NoError(t, err)
	orgCtr := uint64(1)
	csr, err := stCl.CreateState(state.ContractCalyLotteryID, args, *orgDarc, orgCtr, organizer, 3, ed)
	require.NoError(t, err)
	orgCtr++
	ed.UnitSigs[ed.Index] = csr.Sig
	ed.Index++
	gpReply, err := stCl.GetProof(csr.InstanceID, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = gpReply.Sig
	ed.Index++
	require.True(t, gpReply.Proof.InclusionProof.Match(csr.InstanceID[:]))
	_, value, _, _, err := gpReply.Proof.KeyValue()
	storage := state.CalyLotteryStorage{}
	err = protobuf.Decode(value, &storage)
	require.NoError(t, err)
	fmt.Println(storage.SetupData.X.String())
	fmt.Println(storage.SetupData.LTSID)
}

func prepareSpawnArgs(ltsReply *pristore.CreateLTSReply, writers []darc.Signer) ([]*state.KV, error) {
	keyList := make([]string, len(writers))
	for i, w := range writers {
		keyList[i] = w.Ed25519.Point.String()
	}
	klBytes, err := protobuf.Encode(&state.Keys{List: keyList})
	if err != nil {
		log.Errorf("Protobuf encode failed: %v", err)
		return nil, err
	}
	kv := make([]*state.KV, 3)
	kv[0] = &state.KV{Key: "ltsid", Value: ltsReply.Reply.InstanceID[:]}
	kv[1] = &state.KV{Key: "pubkey", Value: []byte(ltsReply.Reply.X.String())}
	kv[2] = &state.KV{Key: "keylist", Value: klBytes}
	return kv, nil
}

func generateWriters(count int) []darc.Signer {
	writers := make([]darc.Signer, count)
	for i := 0; i < count; i++ {
		writers[i] = darc.NewSignerEd25519(nil, nil)
	}
	return writers
}

func generateReaders(count int) []darc.Signer {
	readers := make([]darc.Signer, count)
	for i := 0; i < count; i++ {
		readers[i] = darc.NewSignerEd25519(nil, nil)
	}
	return readers
}

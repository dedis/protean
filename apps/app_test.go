package apps

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"flag"
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
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

var uname string
var sname string
var jname string
var rname string

type TicketData struct {
	C     []byte
	T     []byte
	THash []byte
	K     []byte
	KHash []byte
}

func init() {
	flag.StringVar(&uname, "unit", "", "JSON file")
	flag.StringVar(&sname, "setup", "", "JSON file")
	flag.StringVar(&jname, "join", "", "JSON file")
	flag.StringVar(&rname, "reveal", "", "JSON file")
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

	// BEGIN INITIALIZE UNITS
	// Get directory information from the compiler unit
	compCl := compiler.NewClient(compRoster)
	reply, err := compCl.GetDirectoryInfo()
	require.NoError(t, err)
	directory := reply.Directory

	// PRIVATE STORAGE UNIT
	psName := strings.Replace(pristore.ServiceName, "Service", "", 1)
	val := directory[psName]
	psTxns := utils.ReverseMap(val.Txns)
	cfg := utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, psName, psTxns, 10)

	psCl := pristore.NewClient(unitRoster)
	initReply, err := psCl.InitUnit(cfg)
	require.NoError(t, err)
	for _, node := range unitRoster.List {
		err := psCl.Authorize(node, initReply.ID)
		require.NoError(t, err)
	}
	psCl.Close()

	// STATE UNIT
	stName := strings.Replace(state.ServiceName, "Service", "", 1)
	val = directory[stName]
	stTxns := utils.ReverseMap(val.Txns)
	cfg = utils.GenerateUnitConfig(compRoster.ServicePublics(compiler.ServiceName), unitRoster, val.UnitID, stName, stTxns, 10)

	stCl := state.NewClient(unitRoster)
	_, err = stCl.InitUnit(cfg)
	require.NoError(t, err)
	// END INITIALIZE UNITS

	// BEGIN SETUP WORKFLOW (LOTTERY ORGANIZER)
	setupWf, err := cliutils.PrepareWorkflow(&sname, directory, nil, false)
	require.NoError(t, err)
	planReply, err := compCl.GenerateExecutionPlan(setupWf, nil, nil)
	require.NoError(t, err)
	ed := cliutils.PrepareExecutionData(planReply, nil)

	psCl = pristore.NewClient(unitRoster)
	ltsReply, err := psCl.CreateLTS(unitRoster, 2, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = ltsReply.Sig
	ed.Index++

	writers := generateWriters(4)
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
	stCl = state.NewClient(unitRoster)
	orgDarc := darc.NewDarc(darc.InitRules([]darc.Identity{organizer.Identity()}, []darc.Identity{organizer.Identity()}), []byte("organizer"))
	orgDarc.Rules.AddRule(darc.Action("spawn:"+state.ContractCalyLotteryID), expression.InitOrExpr(organizer.Identity().String()))
	orgDarc.Rules.AddRule(darc.Action("invoke:"+state.ContractCalyLotteryID+".storejoin"), expression.InitOrExpr(writerIDs...))
	sd, err := stCl.SpawnDarc(*orgDarc, 3, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = sd.Sig
	ed.Index++
	args, err := prepareSpawnArgs(ltsReply, writers, lotDarc)
	require.NoError(t, err)
	orgCtr := uint64(1)
	csr, err := stCl.CreateState(state.ContractCalyLotteryID, args, *orgDarc, orgCtr, organizer, 3, ed)
	require.NoError(t, err)
	orgCtr++
	ed.UnitSigs[ed.Index] = csr.Sig
	ed.Index++
	// END SETUP WORKFLOW

	// This is the equivalent of either (1) the organizer putting the CIID
	// information to the workflow beforehand, or (2) the organizer
	// publishing the CIID online and the user retrieving that before
	// starting the execution of the workflow. Either way, it's a local
	// variable on the client-side once it is retrieved.
	iid := csr.InstanceID
	// Run join workflow for N clients, where N is specified somewhere above
	for idx, w := range writers {
		runJoinWorkflow(t, compRoster, unitRoster, directory, idx, iid, w)
	}

	// BEGIN FINALIZE WORKFLOW (LOTTERY ORGANIZER)
	compCl = compiler.NewClient(compRoster)
	revealWf, err := cliutils.PrepareWorkflow(&rname, directory, nil, false)
	require.NoError(t, err)
	revealPlan, err := compCl.GenerateExecutionPlan(revealWf, nil, nil)
	require.NoError(t, err)
	compCl.Close()
	ed = cliutils.PrepareExecutionData(revealPlan, nil)
	stCl = state.NewClient(unitRoster)
	psCl = pristore.NewClient(unitRoster)
	defer stCl.Close()
	defer psCl.Close()

	orgCtr = uint64(1)
	gpReply, err := stCl.GetProof(iid, ed)
	require.NoError(t, err)
	require.True(t, gpReply.ProofResp.Proof.InclusionProof.Match(iid[:]))
	_, value, _, _, err := gpReply.ProofResp.Proof.KeyValue()
	storage := state.CalyLotteryStorage{}
	err = protobuf.Decode(value, &storage)
	require.NoError(t, err)
	lotteryData := storage.LotteryData
	ed.UnitSigs[ed.Index] = gpReply.Sig
	ed.Index++
	wrProofs := getWriteProofs(lotteryData)
	rbReply, err := psCl.AddReadBatch(wrProofs, organizer, orgCtr, 3, ed)
	require.NoError(t, err)
	orgCtr += uint64(len(wrProofs))
	ed.UnitSigs[ed.Index] = rbReply.Sig
	ed.Index++

	gpbReply, err := psCl.GetProofBatch(rbReply.IIDBatch, ed)
	require.NoError(t, err)
	rProofs := getReadProofs(gpbReply.PrBatch)
	//for i, pr := range rProofs {
	//require.True(t, pr.InclusionProof.Match(rbReply.InstanceIDs[i].Slice()))
	//}
	ed.UnitSigs[ed.Index] = gpbReply.Sig
	ed.Index++

	decReply, err := psCl.DecryptBatch(wrProofs, rProofs, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = decReply.Sig
	ed.Index++
	// END FINALIZE WORKFLOW (LOTTERY ORGANIZER)
}

func getReadProofs(prBatch []*pristore.GPR) []*byzcoin.Proof {
	sz := len(prBatch)
	proofs := make([]*byzcoin.Proof, sz)
	for i, pr := range prBatch {
		if pr.Valid {
			proofs[i] = &pr.Resp.Proof
		}
	}
	return proofs
}

func getWriteProofs(wd []state.KV) []*byzcoin.Proof {
	sz := len(wd)
	proofs := make([]*byzcoin.Proof, sz)
	for i, data := range wd {
		wdv := &state.LotteryDataValue{}
		err := protobuf.Decode(data.Value, wdv)
		if err != nil {
			log.Errorf("Protobuf decode error: %v", err)
		} else {
			proofs[i] = wdv.WrProof
		}
	}
	return proofs
}

func runJoinWorkflow(t *testing.T, compRoster *onet.Roster, unitRoster *onet.Roster, directory map[string]*sys.UnitInfo, idx int, iid byzcoin.InstanceID, signer darc.Signer) error {
	// BEGIN JOIN WORKFLOW
	log.Info("Begin join workflow")
	compCl := compiler.NewClient(compRoster)
	joinWf, err := cliutils.PrepareWorkflow(&jname, directory, nil, false)
	require.NoError(t, err)
	joinPlan, err := compCl.GenerateExecutionPlan(joinWf, nil, nil)
	require.NoError(t, err)
	compCl.Close()
	ed := cliutils.PrepareExecutionData(joinPlan, nil)
	stCl := state.NewClient(unitRoster)
	psCl := pristore.NewClient(unitRoster)
	defer stCl.Close()
	defer psCl.Close()

	log.Info("Getting proof")
	gpReply, err := stCl.GetProof(iid, ed)
	require.NoError(t, err)
	require.True(t, gpReply.ProofResp.Proof.InclusionProof.Match(iid[:]))
	_, value, _, _, err := gpReply.ProofResp.Proof.KeyValue()
	storage := state.CalyLotteryStorage{}
	err = protobuf.Decode(value, &storage)
	require.NoError(t, err)
	calyData := storage.SetupData
	ed.UnitSigs[ed.Index] = gpReply.Sig
	ed.Index++

	ticketData, err := prepareLotteryTicket()
	require.NoError(t, err)
	log.Info("Adding write to Calypso")
	//wr, err := psCl.AddWrite(ticketData.K, calyData.LTSID, calyData.X, writers[0], 1, *calyData.CalyDarc, 2, ed)
	log.Info(ticketData.K, calyData.LTSID)
	wr, err := psCl.AddWrite(ticketData.K, calyData.LTSID, calyData.X, signer, 1, *calyData.CalyDarc, 1, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = wr.Sig
	ed.Index++

	wrPr, err := psCl.GetProof(wr.InstanceID, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = wrPr.Sig
	ed.Index++

	//args, err = prepareInvokeArgs(0, ticketData, wrPr.Proof, writers[0].Ed25519.Secret)
	//args, err := prepareInvokeArgs(idx, ticketData, &wrPr.Proof, signer.Ed25519.Secret)
	args, err := prepareInvokeArgs(idx, ticketData, &wrPr.ProofResp.Proof, signer.Ed25519.Secret)
	require.NoError(t, err)
	//updReply, err := stCl.UpdateState(state.ContractCalyLotteryID, args, iid, 1, writers[0], 2, ed)
	updReply, err := stCl.UpdateState(state.ContractCalyLotteryID, "storejoin", args, iid, 1, signer, 1, ed)
	require.NoError(t, err)
	ed.UnitSigs[ed.Index] = updReply.Sig
	ed.Index++
	// END JOIN WORKFLOW
	return nil
}

func prepareLotteryTicket() (*TicketData, error) {
	ticket := make([]byte, 32)
	random.Bytes(ticket, random.New())
	//buf := make([]byte, 44)
	//random.Bytes(buf, random.New())
	//key := buf[:32]
	//nonce := buf[32:]
	key := make([]byte, 24)
	nonce := make([]byte, 12)
	random.Bytes(key, random.New())
	random.Bytes(nonce, random.New())
	// Encrypt ticket using a symmetric key
	aes, err := aes.NewCipher(key)
	if err != nil {
		log.Errorf("Cannot initialize aes")
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(aes)
	if err != nil {
		log.Errorf("Cannot initialize aes-gcm")
		return nil, err
	}
	c := aesgcm.Seal(nil, nonce, ticket, nil)
	c = append(c, nonce...)
	// Compute H(ticket)
	h := sha256.New()
	h.Write(ticket)
	th := h.Sum(nil)
	// Compute H(key)
	h = sha256.New()
	h.Write(key)
	kh := h.Sum(nil)
	return &TicketData{C: c, T: ticket, THash: th, K: key, KHash: kh}, nil
}

func prepareInvokeArgs(idx int, ticketData *TicketData, proof *byzcoin.Proof, sk kyber.Scalar) ([]*state.KV, error) {
	// Prepare WriteDataValue struct
	wdv := &state.WriteDataValue{
		Index:      idx,
		WrProof:    proof,
		Ct:         ticketData.C,
		KeyHash:    ticketData.KHash,
		TicketHash: ticketData.THash,
	}
	wdvBytes, err := protobuf.Encode(wdv)
	if err != nil {
		log.Errorf("Protobuf encode failed: %v", err)
		return nil, err
	}
	// Encode KV version number
	verBuf := make([]byte, 4)
	version := uint32(1)
	binary.LittleEndian.PutUint32(verBuf, version)
	// Compute the hash of (WDV || Version)
	h := sha256.New()
	h.Write(wdvBytes)
	h.Write(verBuf)
	sigData := h.Sum(nil)
	// Perform signing
	sig, err := schnorr.Sign(cothority.Suite, sk, sigData)
	if err != nil {
		log.Errorf("Schnorr sign error: %v", err)
		return nil, err
	}
	kv := make([]*state.KV, 3)
	kv[0] = &state.KV{Key: "data", Value: wdvBytes}
	kv[1] = &state.KV{Key: "sig", Value: sig}
	kv[2] = &state.KV{Key: "version", Value: verBuf}
	return kv, nil
}

func prepareSpawnArgs(ltsReply *pristore.CreateLTSReply, writers []darc.Signer, darc *darc.Darc) ([]*state.KV, error) {
	keyList := make([]string, len(writers))
	for i, w := range writers {
		keyList[i] = w.Ed25519.Point.String()
	}
	klBytes, err := protobuf.Encode(&state.Keys{List: keyList})
	if err != nil {
		log.Errorf("Protobuf encode failed: %v", err)
		return nil, err
	}
	darcBytes, err := protobuf.Encode(darc)
	if err != nil {
		log.Errorf("Protobuf encode failed: %v", err)
		return nil, err
	}
	kv := make([]*state.KV, 4)
	kv[0] = &state.KV{Key: "ltsid", Value: ltsReply.Reply.InstanceID[:]}
	kv[1] = &state.KV{Key: "sharedpk", Value: []byte(ltsReply.Reply.X.String())}
	kv[2] = &state.KV{Key: "keylist", Value: klBytes}
	kv[3] = &state.KV{Key: "calydarc", Value: darcBytes}
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

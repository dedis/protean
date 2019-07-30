package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"time"

	protean "github.com/ceyhunalp/protean_code"
	"github.com/ceyhunalp/protean_code/compiler"
	"github.com/ceyhunalp/protean_code/dummy"
	"github.com/ceyhunalp/protean_code/state"

	//"github.com/ceyhunalp/protean_code/dummy"
	"github.com/ceyhunalp/protean_code/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

func runClient(roster *onet.Roster, genesis []byte, uData map[string]string, tData map[string]string, wfFilePtr *string) error {
	compilerCl := compiler.NewClient()
	//creatScReply, err := compilerCl.CreateSkipchain(roster, 2, 2)
	//if err != nil {
	//return err
	//}
	//fmt.Println("CreateSkipchainReply:", creatScReply.Sb.Hash)
	//unitReply, err := compilerCl.CreateUnits(roster, unitRequest)
	//if err != nil {
	//return err
	//}

	compilerCl.LogSkipchain(roster, genesis)
	for k, v := range uData {
		fmt.Printf("%s - %s\n", k, v)
	}
	fmt.Println("TXNS")
	for k, v := range tData {
		fmt.Printf("%s - %s\n", k, v)
	}

	fmt.Println("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")

	//wf, err := compiler.CreateWorkflow(wfFilePtr, uData, tData)
	wf, err := createWorkflow(wfFilePtr, uData, tData)
	if err != nil {
		return err
	}

	execPlanReply, err := compilerCl.GenerateExecutionPlan(roster, genesis, wf)
	if err != nil {
		return err
	}

	fmt.Println("Sig:", execPlanReply.Signature)
	fmt.Println("Genesis:", execPlanReply.ExecPlan.Genesis)
	fmt.Println("uid:", execPlanReply.ExecPlan.Workflow[0].UID)
	fmt.Println(execPlanReply.ExecPlan.Workflow[1].UID)
	fmt.Println(execPlanReply.ExecPlan.Workflow[2].UID)

	err = utils.VerifySignature(execPlanReply.ExecPlan, execPlanReply.Signature, roster.ServicePublics(compiler.ServiceName))
	if err == nil {
		fmt.Println("Signature verification: SUCCESS")
	} else {
		fmt.Println("Signature verification: FAILED")
	}

	//for _, w := range wf {
	//fmt.Println(w.Index)
	//fmt.Println(w.UId)
	//fmt.Println(w.TId)
	//fmt.Println(w.Deps)
	//fmt.Println("++++++++++")
	//}

	//for _, d := range setupData.Data {
	//fmt.Println("Unit key:", d.UnitKey)
	//for _, t := range d.TxnKeys {
	//fmt.Println("Txn key:", t)
	//}
	//fmt.Println("======")
	//}
	//fmt.Println("First block:", unitReply.SbID)

	//fmt.Println("Sending second time")
	//unitRequest.Units[0].UnitName = "ABBAS"
	//unitRequest.Units[0].Txns[0].TxnName = "KAMIL"
	//unitRequest.Units[0].Txns[1].TxnName = "CABBAR"
	//unitReply, err = compilerCl.RegisterUnits(roster, unitRequest)
	//fmt.Println("Sending second time done")
	//if err != nil {
	//fmt.Println("ERROR:", err)
	//return err
	//}

	//for _, d := range unitReply.Data {
	//fmt.Println("Unit key:", d.UnitKey)
	//for _, t := range d.TxnKeys {
	//fmt.Println("Txn key:", t)
	//}
	//fmt.Println("======")
	//}
	//fmt.Println("Second block:", unitReply.SbID)
	//compilerCl.LogSkipchain(roster)

	return nil
}

func testStateUnit(roster *onet.Roster) error {
	//dumCl := dummy.NewClient()
	stCl := state.NewClient()
	scData := &utils.ScInitData{
		Roster:  roster,
		MHeight: 2,
		BHeight: 2,
	}
	uData := &protean.BaseStorage{
		UInfo: &protean.UnitInfo{
			UnitID:   "state",
			UnitName: "stateUnit",
			Txns:     map[string]string{"a": "b", "c": "d"},
		},
		CompKeys: roster.ServicePublics(state.ServiceName),
	}

	_, err := stCl.InitUnit(roster, scData, uData, 30, time.Second)
	if err != nil {
		fmt.Println("Cannot initialize state unit")
		return err
	}
	//_, err = dumCl.InitByzcoin(roster, 20, time.Second)
	//if err != nil {
	//fmt.Println("Cannot initialize byzcoin")
	//return err
	//}

	org := darc.NewSignerEd25519(nil, nil)
	orgDarc := darc.NewDarc(darc.InitRules([]darc.Identity{org.Identity()}, []darc.Identity{org.Identity()}), []byte("Organizer"))
	cl1 := darc.NewSignerEd25519(nil, nil)
	cl2 := darc.NewSignerEd25519(nil, nil)
	cl3 := darc.NewSignerEd25519(nil, nil)
	fmt.Println("I'm", org.Identity().String())
	fmt.Println("I'm", cl1.Identity().String())
	fmt.Println("I'm", cl2.Identity().String())
	fmt.Println("I'm", cl3.Identity().String())
	orgDarc.Rules.AddRule(darc.Action("spawn:"+state.ContractKeyValueID), expression.InitOrExpr(org.Identity().String()))
	orgDarc.Rules.AddRule(darc.Action("invoke:"+state.ContractKeyValueID+".update"), expression.InitOrExpr(org.Identity().String(), cl1.Identity().String(), cl2.Identity().String()))
	//orgDarc.Rules.AddRule(darc.Action("invoke:"+dummy.ContractKeyValueID+".update"), expression.InitOrExpr(org.Identity().String()))
	_, err = stCl.SpawnDarc(roster, *orgDarc, 5)
	if err != nil {
		fmt.Println("Cannot spawn darc")
		return err
	}

	var kv []*state.KV
	kv = append(kv, &state.KV{Key: "foo1", Value: []byte("bar1")})
	kv = append(kv, &state.KV{Key: "foo2", Value: []byte("bar2")})
	signerCtr := uint64(1)
	//cl1Ctr := uint64(1)
	csReply, err := stCl.CreateState(roster, state.ContractKeyValueID, kv, *orgDarc, signerCtr, org, 4)
	if err != nil {
		return fmt.Errorf("createstaterequest failed: %v", err)
	}
	signerCtr++

	gpReply, err := stCl.GetProof(roster, csReply.InstID)
	if err != nil {
		return fmt.Errorf("getproof failed: %v", err)
	}
	if !gpReply.Proof.InclusionProof.Match(csReply.InstID[:]) {
		return fmt.Errorf("Inclusion proof does not match")
	} else {
		fmt.Println("SUCCESS: Inclusion proof matched")
	}

	_, val, _, _, err := gpReply.Proof.KeyValue()
	storage := state.Storage{}
	err = protobuf.Decode(val, &storage)
	if err != nil {
		return fmt.Errorf("Protobuf decode failed: %v", err)
	}
	fmt.Println("Printing after create state:")
	for _, d := range storage.Data {
		fmt.Println(d.Key, string(d.Value))
	}

	fmt.Println("===============")

	var updKv []*state.KV
	updKv = append(updKv, &state.KV{Key: "foo3", Value: []byte("bar3")})
	updKv = append(updKv, &state.KV{Key: "foo4", Value: []byte("bar4")})

	_, err = stCl.UpdateState(roster, state.ContractKeyValueID, updKv, csReply.InstID, signerCtr, org, 4)
	//_, err = stCl.UpdateState(roster, updKv, csReply.InstID, cl1Ctr, cl1, 4)
	if err != nil {
		return fmt.Errorf("updatestaterequest failed: %v", err)
	}
	//cl1Ctr++
	fmt.Println("Returned from updatestaterequest")

	gpReply, err = stCl.GetProof(roster, csReply.InstID)
	if err != nil {
		return fmt.Errorf("getproof failed: %v", err)
	}
	if !gpReply.Proof.InclusionProof.Match(csReply.InstID[:]) {
		return fmt.Errorf("Inclusion proof does not match")
	}

	_, val, _, _, err = gpReply.Proof.KeyValue()
	storage = state.Storage{}
	err = protobuf.Decode(val, &storage)
	if err != nil {
		return fmt.Errorf("Protobuf decode failed: %v", err)
	}
	for _, d := range storage.Data {
		fmt.Println(d.Key, string(d.Value))
	}
	return nil
}

func testDummyUnit(roster *onet.Roster) error {
	dumCl := dummy.NewClient()
	scData := &utils.ScInitData{
		Roster:  roster,
		MHeight: 2,
		BHeight: 2,
	}
	uData := &protean.BaseStorage{
		UInfo: &protean.UnitInfo{
			UnitID:   "dummy",
			UnitName: "dummyUnit",
			Txns:     map[string]string{"a": "b", "c": "d"},
		},
		CompKeys: roster.ServicePublics(dummy.ServiceName),
	}

	_, err := dumCl.InitUnit(roster, scData, uData, 15, time.Second)
	if err != nil {
		fmt.Println("Cannot initialize state unit")
		return err
	}
	//_, err = dumCl.InitByzcoin(roster, 20, time.Second)
	//if err != nil {
	//fmt.Println("Cannot initialize byzcoin")
	//return err
	//}

	org := darc.NewSignerEd25519(nil, nil)
	orgDarc := darc.NewDarc(darc.InitRules([]darc.Identity{org.Identity()}, []darc.Identity{org.Identity()}), []byte("Organizer"))
	cl1 := darc.NewSignerEd25519(nil, nil)
	cl2 := darc.NewSignerEd25519(nil, nil)
	cl3 := darc.NewSignerEd25519(nil, nil)
	fmt.Println("I'm", org.Identity().String())
	fmt.Println("I'm", cl1.Identity().String())
	fmt.Println("I'm", cl2.Identity().String())
	fmt.Println("I'm", cl3.Identity().String())
	orgDarc.Rules.AddRule(darc.Action("spawn:"+dummy.ContractKeyValueID), expression.InitOrExpr(org.Identity().String()))
	orgDarc.Rules.AddRule(darc.Action("invoke:"+dummy.ContractKeyValueID+".update"), expression.InitOrExpr(org.Identity().String(), cl1.Identity().String(), cl2.Identity().String()))
	//orgDarc.Rules.AddRule(darc.Action("invoke:"+dummy.ContractKeyValueID+".update"), expression.InitOrExpr(org.Identity().String()))
	_, err = dumCl.SpawnDarc(roster, *orgDarc, 5)
	if err != nil {
		fmt.Println("Cannot spawn darc")
		return err
	}

	var kv []*dummy.KV
	kv = append(kv, &dummy.KV{Key: "foo1", Value: []byte("bar1")})
	kv = append(kv, &dummy.KV{Key: "foo2", Value: []byte("bar2")})
	signerCtr := uint64(1)
	cl1Ctr := uint64(1)
	csReply, err := dumCl.CreateState(roster, dummy.ContractKeyValueID, kv, *orgDarc, signerCtr, org, 4)
	if err != nil {
		return fmt.Errorf("createstaterequest failed: %v", err)
	}
	signerCtr++

	gpReply, err := dumCl.GetProof(roster, csReply.InstID)
	if err != nil {
		return fmt.Errorf("getproof failed: %v", err)
	}
	if !gpReply.Proof.InclusionProof.Match(csReply.InstID[:]) {
		return fmt.Errorf("Inclusion proof does not match")
	} else {
		fmt.Println("SUCCESS: Inclusion proof matched")
	}

	_, val, _, _, err := gpReply.Proof.KeyValue()
	storage := dummy.Storage{}
	err = protobuf.Decode(val, &storage)
	if err != nil {
		return fmt.Errorf("Protobuf decode failed: %v", err)
	}
	fmt.Println("Printing after create state:")
	for _, d := range storage.Data {
		fmt.Println(d.Key, string(d.Value))
	}

	fmt.Println("===============")

	var updKv []*dummy.KV
	updKv = append(updKv, &dummy.KV{Key: "foo3", Value: []byte("bar3")})
	updKv = append(updKv, &dummy.KV{Key: "foo4", Value: []byte("bar4")})

	//_, err = dumCl.UpdateState(roster, updKv, csReply.InstID, signerCtr, org, 4)
	_, err = dumCl.UpdateState(roster, dummy.ContractKeyValueID, updKv, csReply.InstID, cl1Ctr, cl1, 4)
	if err != nil {
		return fmt.Errorf("updatestaterequest failed: %v", err)
	}
	//cl1Ctr++
	fmt.Println("Returned from updatestaterequest")

	gpReply, err = dumCl.GetProof(roster, csReply.InstID)
	if err != nil {
		return fmt.Errorf("getproof failed: %v", err)
	}
	if !gpReply.Proof.InclusionProof.Match(csReply.InstID[:]) {
		return fmt.Errorf("Inclusion proof does not match")
	}

	_, val, _, _, err = gpReply.Proof.KeyValue()
	storage = dummy.Storage{}
	err = protobuf.Decode(val, &storage)
	if err != nil {
		return fmt.Errorf("Protobuf decode failed: %v", err)
	}
	for _, d := range storage.Data {
		fmt.Println(d.Key, string(d.Value))
	}
	return nil
}

func test(roster *onet.Roster) error {
	dumCl := dummy.NewClient()
	_, err := dumCl.InitByzcoin(roster, 10, time.Second)
	if err != nil {
		fmt.Println("Cannot initialize byzcoin")
		return err
	}
	org := darc.NewSignerEd25519(nil, nil)
	orgDarc := darc.NewDarc(darc.InitRules([]darc.Identity{org.Identity()}, []darc.Identity{org.Identity()}), []byte("Organizer"))
	cl1 := darc.NewSignerEd25519(nil, nil)
	cl2 := darc.NewSignerEd25519(nil, nil)
	//cl3 := darc.NewSignerEd25519(nil, nil)
	orgDarc.Rules.AddRule(darc.Action("spawn:"+dummy.ContractLotteryID), expression.InitOrExpr(org.Identity().String()))
	orgDarc.Rules.AddRule(darc.Action("invoke:"+dummy.ContractLotteryID+".update"), expression.InitOrExpr(org.Identity().String(), cl1.Identity().String(), cl2.Identity().String()))
	_, err = dumCl.SpawnDarc(roster, *orgDarc, 5)
	if err != nil {
		fmt.Println("Cannot spawn darc")
		return err
	}
	k1, err := encoding.PointToStringHex(cothority.Suite, org.Ed25519.Point)
	if err != nil {
		log.Errorf("Encoding point to hex string failed: %v", err)
		return err
	}
	lv1 := &dummy.LotteryValue{
		Data: []byte("vahit"),
	}
	h := sha256.New()
	h.Write(lv1.Data)
	lv1.Sig, err = org.Sign(h.Sum(nil))
	if err != nil {
		log.Errorf("Error signing: %v", err)
		return nil
	}
	val1, err := protobuf.Encode(lv1)
	if err != nil {
		log.Errorf("Protobuf encode failed: %v", err)
		return err
	}

	var kv []*dummy.KV
	kv = append(kv, &dummy.KV{Key: k1, Value: val1})
	signerCtr := uint64(1)
	csReply, err := dumCl.CreateState(roster, dummy.ContractLotteryID, kv, *orgDarc, signerCtr, org, 4)
	if err != nil {
		return fmt.Errorf("createstaterequest failed: %v", err)
	}
	signerCtr++

	gpReply, err := dumCl.GetProof(roster, csReply.InstID)
	if err != nil {
		return fmt.Errorf("getproof failed: %v", err)
	}
	if !gpReply.Proof.InclusionProof.Match(csReply.InstID[:]) {
		return fmt.Errorf("Inclusion proof does not match")
	} else {
		fmt.Println("SUCCESS: Inclusion proof matched")
	}

	_, val, _, _, err := gpReply.Proof.KeyValue()
	storage := dummy.Storage{}
	err = protobuf.Decode(val, &storage)
	if err != nil {
		return fmt.Errorf("Protobuf decode failed: %v", err)
	}
	fmt.Println("Printing after create state:")
	lv := &dummy.LotteryValue{}
	for _, d := range storage.Data {
		protobuf.Decode(d.Value, lv)
		fmt.Printf("Key %s - Value %s\n", d.Key, string(lv.Data))
	}

	//k2, err := encoding.PointToStringHex(cothority.Suite, cl1.Ed25519.Point)
	//if err != nil {
	//log.Errorf("Encoding point to hex string failed: %v", err)
	//return err
	//}
	cl1Ctr := uint64(1)
	lv2 := &dummy.LotteryValue{
		Data: []byte("kobra"),
	}
	h = sha256.New()
	h.Write(lv2.Data)
	lv2.Sig, err = cl1.Sign(h.Sum(nil))
	if err != nil {
		log.Errorf("Error signing: %v", err)
		return nil
	}
	val2, err := protobuf.Encode(lv2)
	if err != nil {
		log.Errorf("Protobuf encode failed: %v", err)
		return err
	}
	var upd []*dummy.KV
	upd = append(upd, &dummy.KV{Key: k1, Value: val2})
	//upd = append(upd, &dummy.KV{Key: k2, Value: val2})
	_, err = dumCl.UpdateState(roster, dummy.ContractLotteryID, upd, csReply.InstID, cl1Ctr, cl1, 4)
	if err != nil {
		return fmt.Errorf("update state failed: %v", err)
	}
	cl1Ctr++
	gpReply, err = dumCl.GetProof(roster, csReply.InstID)
	if err != nil {
		return fmt.Errorf("getproof failed: %v", err)
	}
	if !gpReply.Proof.InclusionProof.Match(csReply.InstID[:]) {
		return fmt.Errorf("Inclusion proof does not match")
	}

	_, val, _, _, err = gpReply.Proof.KeyValue()
	storage = dummy.Storage{}
	err = protobuf.Decode(val, &storage)
	if err != nil {
		return fmt.Errorf("Protobuf decode failed: %v", err)
	}
	fmt.Println("Printing after update state:")
	lv = &dummy.LotteryValue{}
	for _, d := range storage.Data {
		protobuf.Decode(d.Value, lv)
		fmt.Printf("Key %s - Value %s\n", d.Key, string(lv.Data))
	}

	return nil
}

func main() {
	rosterFilePtr := flag.String("r", "", "roster.toml file")
	unitFilePtr := flag.String("u", "", "units.txt file")
	txnFilePtr := flag.String("t", "", "txns.txt file")
	wfFilePtr := flag.String("w", "", "workflow.txt file")
	testPtr := flag.Bool("e", false, "test?")
	flag.Parse()

	roster, err := utils.ReadRoster(rosterFilePtr)
	if err != nil {
		os.Exit(1)
	}
	if *testPtr == false {
		genesis, uData, tData, err := setup(roster, unitFilePtr, txnFilePtr)
		if err != nil {
			os.Exit(1)
		}
		runClient(roster, genesis, uData, tData, wfFilePtr)
	} else {
		//TODO: Maybe write a function to fetch latest block information
		//from the skipchain, so that the client can have unit&txn
		//information
		//err := testDummyUnit(roster)
		//err := testStateUnit(roster)
		test(roster)
	}
}

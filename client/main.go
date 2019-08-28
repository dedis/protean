package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dedis/protean"
	clutil "github.com/dedis/protean/client/utils"
	"github.com/dedis/protean/compiler"
	"github.com/dedis/protean/dummy"
	"github.com/dedis/protean/easyneff"
	"github.com/dedis/protean/pristore"
	"github.com/dedis/protean/state"
	"github.com/dedis/protean/tdh"
	"github.com/dedis/protean/threshold"

	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/kyber/v3/util/random"
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

	for k, v := range uData {
		fmt.Printf("%s - %s\n", k, v)
	}
	fmt.Println("TXNS")
	for k, v := range tData {
		fmt.Printf("%s - %s\n", k, v)
	}

	fmt.Println("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")

	//wf, err := compiler.CreateWorkflow(wfFilePtr, uData, tData)
	wf, err := clutil.CreateWorkflow(wfFilePtr, uData, tData)
	if err != nil {
		return err
	}

	execPlanReply, err := compilerCl.GenerateExecutionPlan(wf)
	if err != nil {
		return err
	}

	fmt.Println("Sig:", execPlanReply.Signature)
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
	stCl := state.NewClient()
	scData := &protean.ScInitData{
		//Roster:  roster,
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
	//_, err = dumCl.InitByzcoin(20, time.Second)
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
	_, err = stCl.SpawnDarc(*orgDarc, 5)
	if err != nil {
		fmt.Println("Cannot spawn darc")
		return err
	}

	var kv []*state.KV
	kv = append(kv, &state.KV{Key: "foo1", Value: []byte("bar1")})
	kv = append(kv, &state.KV{Key: "foo2", Value: []byte("bar2")})
	signerCtr := uint64(1)
	//cl1Ctr := uint64(1)
	csReply, err := stCl.CreateState(state.ContractKeyValueID, kv, *orgDarc, signerCtr, org, 4)
	if err != nil {
		return fmt.Errorf("createstaterequest failed: %v", err)
	}
	signerCtr++

	gpReply, err := stCl.GetProof(csReply.InstanceID)
	if err != nil {
		return fmt.Errorf("getproof failed: %v", err)
	}
	if !gpReply.Proof.InclusionProof.Match(csReply.InstanceID[:]) {
		return fmt.Errorf("Inclusion proof does not match")
	}
	fmt.Println("SUCCESS: Inclusion proof matched")

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

	_, err = stCl.UpdateState(state.ContractKeyValueID, updKv, csReply.InstanceID, signerCtr, org, 4)
	//_, err = stCl.UpdateState(updKv, csReply.InstanceID, cl1Ctr, cl1, 4)
	if err != nil {
		return fmt.Errorf("updatestaterequest failed: %v", err)
	}
	//cl1Ctr++
	fmt.Println("Returned from updatestaterequest")

	gpReply, err = stCl.GetProof(csReply.InstanceID)
	if err != nil {
		return fmt.Errorf("getproof failed: %v", err)
	}
	if !gpReply.Proof.InclusionProof.Match(csReply.InstanceID[:]) {
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
	scData := &protean.ScInitData{
		//Roster:  roster,
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

	_, err := dumCl.InitUnit(roster, scData, uData, 10, time.Second)
	if err != nil {
		fmt.Println("Cannot initialize state unit")
		return err
	}
	//_, err = dumCl.InitByzcoin(20, time.Second)
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
	_, err = dumCl.SpawnDarc(*orgDarc, 5)
	if err != nil {
		fmt.Println("Cannot spawn darc")
		return err
	}

	var kv []*dummy.KV
	kv = append(kv, &dummy.KV{Key: "foo1", Value: []byte("bar1")})
	kv = append(kv, &dummy.KV{Key: "foo2", Value: []byte("bar2")})
	signerCtr := uint64(1)
	cl1Ctr := uint64(1)
	csReply, err := dumCl.CreateState(dummy.ContractKeyValueID, kv, *orgDarc, signerCtr, org, 4)
	if err != nil {
		return fmt.Errorf("createstaterequest failed: %v", err)
	}
	signerCtr++

	gpReply, err := dumCl.GetProof(csReply.InstanceID)
	if err != nil {
		return fmt.Errorf("getproof failed: %v", err)
	}
	if !gpReply.Proof.InclusionProof.Match(csReply.InstanceID[:]) {
		return fmt.Errorf("Inclusion proof does not match")
	}
	fmt.Println("SUCCESS: Inclusion proof matched")

	_, val, _, _, err := gpReply.Proof.KeyValue()
	//storage := dummy.Storage{}
	storage := dummy.KVStorage{}
	err = protobuf.Decode(val, &storage)
	if err != nil {
		return fmt.Errorf("Protobuf decode failed: %v", err)
	}
	fmt.Println("Printing after create state:")
	//for _, d := range storage.Data {
	for _, kv := range storage.KV {
		fmt.Println(kv.Key, string(kv.Value))
	}

	fmt.Println("===============")

	var updKv []*dummy.KV
	updKv = append(updKv, &dummy.KV{Key: "foo3", Value: []byte("bar3")})
	updKv = append(updKv, &dummy.KV{Key: "foo4", Value: []byte("bar4")})

	//_, err = dumCl.UpdateState(updKv, csReply.InstanceID, signerCtr, org, 4)
	_, err = dumCl.UpdateState(dummy.ContractKeyValueID, updKv, csReply.InstanceID, cl1Ctr, cl1, 4)
	if err != nil {
		return fmt.Errorf("updatestaterequest failed: %v", err)
	}
	//cl1Ctr++
	fmt.Println("Returned from updatestaterequest")

	gpReply, err = dumCl.GetProof(csReply.InstanceID)
	if err != nil {
		return fmt.Errorf("getproof failed: %v", err)
	}
	if !gpReply.Proof.InclusionProof.Match(csReply.InstanceID[:]) {
		return fmt.Errorf("Inclusion proof does not match")
	}

	_, val, _, _, err = gpReply.Proof.KeyValue()
	//storage = dummy.Storage{}
	storage = dummy.KVStorage{}
	err = protobuf.Decode(val, &storage)
	if err != nil {
		return fmt.Errorf("Protobuf decode failed: %v", err)
	}
	//for _, d := range storage.Data {
	for _, kv := range storage.KV {
		fmt.Println(kv.Key, string(kv.Value))
	}
	return nil
}

func test(roster *onet.Roster) error {
	dumCl := dummy.NewClient()
	_, err := dumCl.InitByzcoin(10, time.Second)
	if err != nil {
		return fmt.Errorf("Cannot initialize byzcoin %v", err)
	}
	org := darc.NewSignerEd25519(nil, nil)
	orgDarc := darc.NewDarc(darc.InitRules([]darc.Identity{org.Identity()}, []darc.Identity{org.Identity()}), []byte("Organizer"))
	cl1 := darc.NewSignerEd25519(nil, nil)
	cl2 := darc.NewSignerEd25519(nil, nil)
	//cl3 := darc.NewSignerEd25519(nil, nil)
	err = orgDarc.Rules.AddRule(darc.Action("spawn:"+dummy.ContractLotteryID), expression.InitOrExpr(org.Identity().String()))
	if err != nil {
		return fmt.Errorf("Add rule to darc failed: %v", err)
	}
	err = orgDarc.Rules.AddRule(darc.Action("invoke:"+dummy.ContractLotteryID+".update"), expression.InitOrExpr(org.Identity().String(), cl1.Identity().String(), cl2.Identity().String()))
	if err != nil {
		return fmt.Errorf("Add rule to darc failed: %v", err)
	}
	_, err = dumCl.SpawnDarc(*orgDarc, 5)
	if err != nil {
		return fmt.Errorf("Cannot spawn darc: %v", err)
	}
	k1, err := encoding.PointToStringHex(cothority.Suite, org.Ed25519.Point)
	if err != nil {
		return fmt.Errorf("Encoding point to hex string failed: %v", err)
	}
	lv1 := &dummy.LotteryValue{
		Data: []byte("vahit"),
	}
	h := sha256.New()
	h.Write(lv1.Data)
	lv1.Sig, err = org.Sign(h.Sum(nil))
	if err != nil {
		return fmt.Errorf("Error signing: %v", err)
	}
	val1, err := protobuf.Encode(lv1)
	if err != nil {
		return err
	}

	var kv []*dummy.KV
	kv = append(kv, &dummy.KV{Key: k1, Value: val1})
	signerCtr := uint64(1)
	csReply, err := dumCl.CreateState(dummy.ContractLotteryID, kv, *orgDarc, signerCtr, org, 4)
	if err != nil {
		return fmt.Errorf("createstaterequest failed: %v", err)
	}
	signerCtr++

	gpReply, err := dumCl.GetProof(csReply.InstanceID)
	if err != nil {
		return fmt.Errorf("getproof failed: %v", err)
	}
	log.Info("IID is:", csReply.InstanceID)
	if !gpReply.Proof.InclusionProof.Match(csReply.InstanceID[:]) {
		return fmt.Errorf("Inclusion proof does not match")
	}
	fmt.Println("SUCCESS: Inclusion proof matched")

	_, val, _, _, err := gpReply.Proof.KeyValue()
	storage := dummy.KVStorage{}
	err = protobuf.Decode(val, &storage)
	if err != nil {
		return fmt.Errorf("Protobuf decode failed: %v", err)
	}
	fmt.Println("Printing after create state:")
	lv := &dummy.LotteryValue{}
	for _, kv := range storage.KV {
		protobuf.Decode(kv.Value, lv)
		fmt.Printf("Key %s - Value %s\n", kv.Key, string(lv.Data))
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
		return fmt.Errorf("Error signing: %v", err)
	}
	val2, err := protobuf.Encode(lv2)
	if err != nil {
		return err
	}
	var upd []*dummy.KV
	upd = append(upd, &dummy.KV{Key: k1, Value: val2})
	//upd = append(upd, &dummy.KV{Key: k2, Value: val2})
	_, err = dumCl.UpdateState(dummy.ContractLotteryID, upd, csReply.InstanceID, cl1Ctr, cl1, 4)
	if err != nil {
		return fmt.Errorf("update state failed: %v", err)
	}
	cl1Ctr++
	gpReply, err = dumCl.GetProof(csReply.InstanceID)
	if err != nil {
		return fmt.Errorf("getproof failed: %v", err)
	}
	if !gpReply.Proof.InclusionProof.Match(csReply.InstanceID[:]) {
		return fmt.Errorf("Inclusion proof does not match")
	}

	_, val, _, _, err = gpReply.Proof.KeyValue()
	storage = dummy.KVStorage{}
	err = protobuf.Decode(val, &storage)
	if err != nil {
		return fmt.Errorf("Protobuf decode failed: %v", err)
	}
	fmt.Println("Printing after update state:")
	lv = &dummy.LotteryValue{}
	for _, kv := range storage.KV {
		protobuf.Decode(kv.Value, lv)
		fmt.Printf("Key %s - Value %s\n", kv.Key, string(lv.Data))
	}
	return nil
}

func testPristore(roster *onet.Roster) error {
	psCl := pristore.NewClient()
	scData := &protean.ScInitData{
		//Roster:  roster,
		MHeight: 2,
		BHeight: 2,
	}
	uData := &protean.BaseStorage{
		UInfo: &protean.UnitInfo{
			UnitID:   "pristore",
			UnitName: "pristoreUnit",
			Txns:     map[string]string{"a": "b", "c": "d"},
		},
		CompKeys: roster.ServicePublics(pristore.ServiceName),
	}

	reply, err := psCl.InitUnit(roster, scData, uData, 15, time.Second)
	if err != nil {
		return fmt.Errorf("InitUnit error: %v", err)
	}
	for _, who := range roster.List {
		err := psCl.Authorize(who, reply.ID)
		if err != nil {
			return fmt.Errorf("Authorize error: %v", err)
		}
	}
	err = psCl.CreateLTS(roster, 4)
	if err != nil {
		return fmt.Errorf("CreateLTS error: %v", err)
	}

	provider1 := darc.NewSignerEd25519(nil, nil)
	reader1 := darc.NewSignerEd25519(nil, nil)
	provider2 := darc.NewSignerEd25519(nil, nil)
	//reader2 := darc.NewSignerEd25519(nil, nil)

	//TODO: Client side should not be using calypso!
	// Move it inside the API
	darc1 := darc.NewDarc(darc.InitRules([]darc.Identity{provider1.Identity()}, []darc.Identity{provider1.Identity()}), []byte("Provider1"))
	err = darc1.Rules.AddRule(darc.Action("spawn:"+calypso.ContractWriteID), expression.InitOrExpr(provider1.Identity().String(), provider2.Identity().String()))
	if err != nil {
		return fmt.Errorf("Add rule to darc failed: %v", err)
	}
	err = darc1.Rules.AddRule(darc.Action("spawn:"+calypso.ContractReadID), expression.InitOrExpr(reader1.Identity().String()))
	if err != nil {
		return fmt.Errorf("Add rule to darc failed: %v", err)
	}
	_, err = psCl.SpawnDarc(*darc1, 4)
	if err != nil {
		return fmt.Errorf("SpawnDarc error: %v", err)
	}
	data := []byte("On Wisconsin!")
	data2 := []byte("Go Badgers!")
	//wr1, err := psCl.AddWrite(darc1.GetBaseID(), data, provider1, 1, *darc1, 4)
	wr1, err := psCl.AddWrite(data, provider1, 1, *darc1, 4)
	if err != nil {
		return fmt.Errorf("AddWrite error: %v", err)
	}
	wpReply, err := psCl.GetProof(wr1.InstanceID)
	if err != nil {
		return fmt.Errorf("Proof does not exist: %v", err)
	}
	log.Info(wr1.InstanceID)
	wr2, err := psCl.AddWrite(data2, provider2, 1, *darc1, 4)
	if err != nil {
		return fmt.Errorf("AddWrite error: %v", err)
	}
	log.Info(wr2.InstanceID)
	_, err = psCl.GetProof(wr2.InstanceID)
	if err != nil {
		return fmt.Errorf("Proof does not exist: %v", err)
	}
	re1, err := psCl.AddRead(&wpReply.Proof, reader1, 1, 4)
	if err != nil {
		return fmt.Errorf("AddRead error: %v", err)
	}
	rpReply, err := psCl.GetProof(re1.InstanceID)
	if err != nil {
		return fmt.Errorf("Proof does not exist: %v", err)
	}
	if !rpReply.Proof.InclusionProof.Match(re1.InstanceID.Slice()) {
		return fmt.Errorf("Inclusion proof does not match")
	}
	fmt.Println("SUCCESS: Inclusion proof matched")

	dk, err := psCl.Decrypt(wpReply.Proof, rpReply.Proof)
	if err != nil {
		return fmt.Errorf("Decrypt error: %v", err)
	}
	//ptext, err := psCl.RecoverKey(dk, reader1)
	ptext, err := dk.RecoverKey(reader1)
	if err != nil {
		return fmt.Errorf("DecodeKey error: %v", err)
	}
	fmt.Println("Recovered:", string(ptext))
	return nil
}

func testShuffle(roster *onet.Roster) error {
	neffCl := easyneff.NewClient()
	scData := &protean.ScInitData{
		//Roster:  roster,
		MHeight: 2,
		BHeight: 2,
	}
	uData := &protean.BaseStorage{
		UInfo: &protean.UnitInfo{
			UnitID:   "shuffle",
			UnitName: "shuffleUnit",
			Txns:     map[string]string{"a": "b", "c": "d"},
		},
		CompKeys: roster.ServicePublics(easyneff.ServiceName),
	}

	_, err := neffCl.InitUnit(roster, scData, uData, 10, time.Second)
	if err != nil {
		return fmt.Errorf("InitUnit error: %v", err)
	}

	pairs, g, h := generateReq(10, []byte("On Wisconsin"))
	reply, err := neffCl.Shuffle(pairs, g, h)
	if err != nil {
		return fmt.Errorf("shuffle error: %v", err)
	}
	fmt.Println("Length of proofs:", len(reply.Proofs))
	err = reply.ShuffleVerify(g, h, pairs, roster.Publics())
	if err != nil {
		return fmt.Errorf("Shuffle verify error: %v", err)
	}

	return nil
}

func testTDH(roster *onet.Roster) error {
	tdhCl := tdh.NewClient()
	scData := &protean.ScInitData{
		MHeight: 2,
		BHeight: 2,
	}
	uData := &protean.BaseStorage{
		UInfo: &protean.UnitInfo{
			UnitID:   "tdh",
			UnitName: "tdhUnit",
			Txns:     map[string]string{"a": "b", "c": "d"},
		},
		CompKeys: roster.ServicePublics(tdh.ServiceName),
	}

	gen := make([]byte, 32)
	random.Bytes(gen, random.New())
	keyPair := darc.NewSignerEd25519(nil, nil)
	mesg := []byte("Go Badgers! On Wisconsin!")
	// Returns Schnorr signature
	sig, err := keyPair.Sign(mesg)
	if err != nil {
		return fmt.Errorf("Sign failed: %v", err)
	}
	//fmt.Println("Signature:", sig)
	//fmt.Println("Length:", len(sig))

	_, err = tdhCl.InitUnit(roster, scData, uData, 10, time.Second)
	if err != nil {
		return fmt.Errorf("InitUnit error: %v", err)
	}
	dkgReply, err := tdhCl.InitDKG(sig)
	if err != nil {
		return fmt.Errorf("InitDKG error: %v", err)
	}
	fmt.Println("Key is", dkgReply.X.String())
	//ctext := tdhCl.Encrypt(cothority.Suite, gen, dkgReply.X, mesg)
	ctext := tdh.Encrypt(cothority.Suite, gen, dkgReply.X, mesg)
	//decReply, err := tdhCl.Decrypt(sig, gen[:], ctext.C, ctext.U, keyPair.Ed25519.Point)
	decReply, err := tdhCl.Decrypt(sig, gen, ctext, keyPair.Ed25519.Point)
	if err != nil {
		return fmt.Errorf("Decrypt error: %v", err)
	}
	//data, err := tdhCl.RecoverPlaintext(decReply, keyPair.Ed25519.Secret)
	data, err := tdh.RecoverPlaintext(decReply, keyPair.Ed25519.Secret)
	if err != nil {
		return fmt.Errorf("Data error: %v", err)
	}
	fmt.Println("Data is:", string(data))

	///// Failing decryption test

	kp := darc.NewSignerEd25519(nil, nil)
	mesg = []byte("Peanut butter jelly time!")
	// Returns Schnorr signature
	sig2, err := kp.Sign(mesg)
	if err != nil {
		return fmt.Errorf("Sign failed: %v", err)
	}
	dkgReply, err = tdhCl.InitDKG(sig2)
	if err != nil {
		return fmt.Errorf("InitDKG error: %v", err)
	}
	fmt.Println("Key is", dkgReply.X.String())
	//ctext = tdhCl.Encrypt(cothority.Suite, gen, dkgReply.X, mesg)
	ctext = tdh.Encrypt(cothority.Suite, gen, dkgReply.X, mesg)
	//decReply, err = tdhCl.Decrypt(sig, gen[:], ctext.C, ctext.U, kp.Ed25519.Point)
	random.Bytes(gen, random.New())
	decReply, err = tdhCl.Decrypt(sig2, gen, ctext, kp.Ed25519.Point)
	if err != nil {
		return fmt.Errorf("Decrypt error: %v", err)
	}
	//data, err = tdhCl.RecoverPlaintext(decReply, kp.Ed25519.Secret)
	data, err = tdh.RecoverPlaintext(decReply, kp.Ed25519.Secret)
	if err != nil {
		return fmt.Errorf("Data error: %v", err)
	}
	fmt.Println("Data is:", string(data))
	return nil
}

func testThreshold(roster *onet.Roster) error {
	thresholdCl := threshold.NewClient()
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
		CompKeys: roster.ServicePublics(threshold.ServiceName),
	}

	keyPair := darc.NewSignerEd25519(nil, nil)

	var mesgs [][]byte
	mesgs = append(mesgs, []byte("Robert Glasper Experiment!"))
	mesgs = append(mesgs, []byte("On Wisconsin!"))
	mesgs = append(mesgs, []byte("Lotus Feet?"))

	// Returns Schnorr signature
	sig, err := keyPair.Sign(mesgs[0])
	if err != nil {
		return fmt.Errorf("Sign failed: %v", err)
	}

	_, err = thresholdCl.InitUnit(roster, scData, uData, 10, time.Second)
	if err != nil {
		return fmt.Errorf("InitUnit error: %v", err)
	}
	dkgReply, err := thresholdCl.InitDKG(sig)
	if err != nil {
		return fmt.Errorf("InitDKG error: %v", err)
	}
	cs := make([]*utils.ElGamalPair, len(mesgs))
	for i, mesg := range mesgs {
		c := utils.ElGamalEncrypt(dkgReply.X, mesg)
		cs[i] = &c
	}

	time.Sleep(5 * time.Second)

	_, err = thresholdCl.Decrypt([]byte("badreq"), cs, true)
	if err != nil {
		fmt.Println("Decrypt request failed:", err)
	}

	time.Sleep(5 * time.Second)

	decReply, err := thresholdCl.Decrypt(sig, cs, true)
	if err != nil {
		return fmt.Errorf("Decrypt error: %v", err)
	}
	for _, p := range decReply.Ps {
		pt, err := p.Data()
		if err != nil {
			return fmt.Errorf("Cannot get plaintext from curve point: %v", err)
		}
		fmt.Println("Data is:", string(pt))
	}

	decReply, err = thresholdCl.Decrypt(sig, cs, false)
	if err != nil {
		return fmt.Errorf("Decrypt error: %v", err)
	}
	fmt.Println("----------")
	ps := threshold.RecoverMessages(len(roster.List), cs, decReply.Partials)
	for _, p := range ps {
		pt, err := p.Data()
		if err != nil {
			log.Errorf("Cannot get plaintext from curve point: %v", err)
		} else {
			fmt.Println("Data is:", string(pt))
		}
	}
	return nil
}

//func generateReq(n int, msg []byte) ([]easyneff.ElGamalPair, kyber.Point, kyber.Point) {
func generateReq(n int, msg []byte) ([]utils.ElGamalPair, kyber.Point, kyber.Point) {
	r := random.New()
	//pairs := make([]easyneff.ElGamalPair, n)
	pairs := make([]utils.ElGamalPair, n)
	for i := range pairs {
		secret := cothority.Suite.Scalar().Pick(r)
		public := cothority.Suite.Point().Mul(secret, nil)
		c := utils.ElGamalEncrypt(public, msg)
		//pairs[i] = easyneff.ElGamalPair{C1: c.K, C2: c.C}
		pairs[i] = utils.ElGamalPair{K: c.K, C: c.C}
	}
	return pairs, cothority.Suite.Point().Base(), cothority.Suite.Point().Pick(r)
}

func testFail(roster *onet.Roster) error {
	psCl := pristore.NewClient()
	scData := &protean.ScInitData{
		MHeight: 2,
		BHeight: 2,
	}
	uData := &protean.BaseStorage{
		UInfo: &protean.UnitInfo{
			UnitID:   "pristore",
			UnitName: "pristoreUnit",
			Txns:     map[string]string{"a": "b", "c": "d"},
		},
		CompKeys: roster.ServicePublics(pristore.ServiceName),
	}

	reply, err := psCl.InitUnit(roster, scData, uData, 15, time.Second)
	if err != nil {
		return fmt.Errorf("InitUnit error: %v", err)
	}
	for _, who := range roster.List {
		err := psCl.Authorize(who, reply.ID)
		if err != nil {
			return fmt.Errorf("Authorize error: %v", err)
		}
	}
	err = psCl.CreateLTS(roster, 4)
	if err != nil {
		return fmt.Errorf("CreateLTS error: %v", err)
	}

	provider1 := darc.NewSignerEd25519(nil, nil)
	reader1 := darc.NewSignerEd25519(nil, nil)
	//provider2 := darc.NewSignerEd25519(nil, nil)

	darc1 := darc.NewDarc(darc.InitRules([]darc.Identity{provider1.Identity()}, []darc.Identity{provider1.Identity()}), []byte("Provider1"))
	err = darc1.Rules.AddRule(darc.Action("spawn:"+calypso.ContractWriteID), expression.InitOrExpr(provider1.Identity().String()))
	if err != nil {
		return fmt.Errorf("Add rule to darc failed: %v", err)
	}
	err = darc1.Rules.AddRule(darc.Action("spawn:"+calypso.ContractReadID), expression.InitOrExpr(reader1.Identity().String()))
	if err != nil {
		return fmt.Errorf("Add rule to darc failed: %v", err)
	}
	_, err = psCl.SpawnDarc(*darc1, 4)
	if err != nil {
		return fmt.Errorf("SpawnDarc error: %v", err)
	}
	data := []byte("On Wisconsin!")
	wr1, err := psCl.AddWrite(data, provider1, 1, *darc1, 4)
	if err != nil {
		return fmt.Errorf("AddWrite error: %v", err)
	}
	wpReply, err := psCl.GetProof(wr1.InstanceID)
	if err != nil {
		return fmt.Errorf("Proof does not exist: %v", err)
	}
	re1, err := psCl.AddRead(&wpReply.Proof, reader1, 1, 4)
	if err != nil {
		return fmt.Errorf("AddRead error: %v", err)
	}
	rpReply, err := psCl.GetProof(re1.InstanceID)
	if err != nil {
		return fmt.Errorf("Proof does not exist: %v", err)
	}
	if !rpReply.Proof.InclusionProof.Match(re1.InstanceID.Slice()) {
		return fmt.Errorf("Inclusion proof does not match")
	}
	fmt.Println("SUCCESS: Inclusion proof matched")

	dk, err := psCl.Decrypt(wpReply.Proof, rpReply.Proof)
	if err != nil {
		return fmt.Errorf("Decrypt error: %v", err)
	}
	//ptext, err := psCl.RecoverKey(dk, reader1)
	ptext, err := dk.RecoverKey(reader1)
	if err != nil {
		return fmt.Errorf("DecodeKey error: %v", err)
	}
	fmt.Println("Recovered:", string(ptext))
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
		genesis, uData, tData, err := clutil.Setup(roster, unitFilePtr, txnFilePtr)
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
		//err := test(roster)
		//err := testPristore(roster)
		//err := testShuffle(roster)
		//err := testTDH(roster)
		//err := testThreshold(roster)
		//err := testSigver(roster)
		err := testFail(roster)
		if err != nil {
			fmt.Println(err)
		}
	}
}

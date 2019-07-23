package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ceyhunalp/protean_code"
	"github.com/ceyhunalp/protean_code/compiler"
	"github.com/ceyhunalp/protean_code/dummy"
	"github.com/ceyhunalp/protean_code/utils"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"
	"go.dedis.ch/onet/v3"
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
	dumCl := dummy.NewClient()
	scData := &utils.ScInitData{
		Roster:  roster,
		MHeight: 2,
		BHeight: 2,
	}
	uData := &protean.UnitStorage{
		UnitID:   "dummy",
		Txns:     map[string]string{"a": "b", "c": "d"},
		CompKeys: roster.ServicePublics(dummy.ServiceName),
	}
	//_, err := dumCl.InitUnit(roster, 15, time.Second)
	_, err := dumCl.InitUnit(roster, scData, uData, 15, time.Second)
	if err != nil {
		fmt.Println("Cannot initialize state unit")
		return err
	}

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
	//orgDarc.Rules.AddRule(darc.Action("invoke:"+dummy.ContractKeyValueID+".update"), expression.InitOrExpr(cl1.Identity().String()))
	//orgDarc.Rules.AddRule(darc.Action("invoke:"+dummy.ContractKeyValueID+".update"), expression.InitOrExpr(cl2.Identity().String()))
	_, err = dumCl.SpawnDarc(roster, *orgDarc, 5)
	if err != nil {
		fmt.Println("Cannot spawn darc")
		return err
	}

	var kv []*dummy.KV
	kv = append(kv, &dummy.KV{Key: "deli", Value: []byte("vahit")})
	kv = append(kv, &dummy.KV{Key: "pasa", Value: []byte("vahit")})
	signerCtr := uint64(1)
	cl1Ctr := uint64(1)
	csReply, err := dumCl.CreateState(roster, kv, *orgDarc, signerCtr, org, 4)
	if err != nil {
		return fmt.Errorf("createstaterequest failed: %v", err)
	}
	signerCtr++

	gpReply, err := dumCl.GetProof(roster, csReply.InstID[:])
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
	for k, v := range storage.Data {
		fmt.Println(k, string(v))
	}

	fmt.Println("===============")

	var updKv []*dummy.KV
	updKv = append(updKv, &dummy.KV{Key: "erkan", Value: []byte("ogur")})
	updKv = append(updKv, &dummy.KV{Key: "terence", Value: []byte("blanchard")})

	_, err = dumCl.UpdateState(roster, updKv, csReply.InstID, cl1Ctr, cl3, 4)
	//_, err = dumCl.UpdateStateRequest(roster, updKv, csReply.InstID, signerCtr, org)
	if err != nil {
		return fmt.Errorf("updatestaterequest failed: %v", err)
	}
	cl1Ctr++
	fmt.Println("Returned from updatestaterequest")

	gpReply, err = dumCl.GetProof(roster, csReply.InstID[:])
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
	for k, v := range storage.Data {
		fmt.Println(k, string(v))
	}
	return nil
}

func main() {
	rosterFilePtr := flag.String("r", "", "roster.toml file")
	unitFilePtr := flag.String("u", "", "units.txt file")
	txnFilePtr := flag.String("t", "", "txns.txt file")
	wfFilePtr := flag.String("w", "", "workflow.txt file")
	setupPtr := flag.Bool("s", false, "set up already?")
	flag.Parse()

	roster, err := utils.ReadRoster(rosterFilePtr)
	if err != nil {
		os.Exit(1)
	}

	//for i := 0; i < len(roster.List); i++ {
	//fmt.Print(roster.List[i], " ")
	//}
	//fmt.Println()

	//for _, r := range roster.List {
	//fmt.Println(r.ID, r.String())
	//}

	if *setupPtr != true {
		genesis, uData, tData, err := setup(roster, unitFilePtr, txnFilePtr)
		if err != nil {
			os.Exit(1)
		}
		runClient(roster, genesis, uData, tData, wfFilePtr)
	} else {
		//TODO: Maybe write a function to fetch latest block information
		//from the skipchain, so that the client can have unit&txn
		//information
		err := testStateUnit(roster)
		if err != nil {
			fmt.Println(err)
		}
	}

	//runClient(roster, unitRequest)

	//roster, err := utils.ReadRoster(filePtr)
	//pubs := roster.Publics()
	//fmt.Println("===== Printing the output of ReadRoster.Publics() =====")
	//fmt.Println(pubs)
	//if err != nil {
	//log.Errorf("Reading roster failed: %v", err)
	//os.Exit(1)
	//}

	//cl := blscosi.NewClient()
	//suite := cl.Suite().(*pairing.SuiteBn256)
	//msg := []byte("Hello from the other side")

	//reply, err := cl.SignatureRequest(roster, msg)
	//if err != nil {
	//log.Errorf("Signature request failed: %v", err)
	//os.Exit(1)
	//}
	//fmt.Println("===== Printing the publics of blscosi service =====")
	//publics := roster.ServicePublics(blscosi.ServiceName)
	//for i := 0; i < len(publics); i++ {
	//fmt.Println(publics[i])
	//}
	//fmt.Println("===== Printing the publics of byzcoin service =====")
	//byzPubs := roster.ServicePublics(byzcoin.ServiceName)
	//for i := 0; i < len(byzPubs); i++ {
	//fmt.Println(byzPubs[i])
	//}

	//fmt.Println("===== Verifying with the blscosi publics =====")
	//err = reply.Signature.Verify(suite, msg, publics)
	//if err != nil {
	//log.Errorf("Verification failed: %v", err)
	//os.Exit(1)
	//} else {
	//fmt.Println("====== Verification success ======")
	//fmt.Println(reply.Signature)
	//}
}

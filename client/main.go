package main

import (
	"flag"
	"fmt"
	"github.com/ceyhunalp/protean_code/compiler"
	"github.com/ceyhunalp/protean_code/utils"
	//"go.dedis.ch/cothority/v3/blscosi"
	//"go.dedis.ch/cothority/v3/byzcoin"
	//"go.dedis.ch/cothority/v3/skipchain"
	//"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3"
	//"go.dedis.ch/onet/v3/log"
	"os"
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

	wf, err := utils.CreateWorkflow(wfFilePtr, uData, tData)
	if err != nil {
		return err
	}

	compilerCl.GenerateExecutionPlan(roster, genesis, wf)

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
		genesis, uData, tData, err := utils.Setup(roster, unitFilePtr, txnFilePtr)
		if err != nil {
			os.Exit(1)
		}
		runClient(roster, genesis, uData, tData, wfFilePtr)
	} else {
		//TODO: Maybe write a function to fetch latest block information
		//from the skipchain, so that the client can have unit&txn
		//information
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

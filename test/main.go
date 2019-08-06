package main

//"flag"
//"fmt"
//"go.dedis.ch/cothority/v3/blscosi"
//"go.dedis.ch/cothority/v3/byzcoin"
//"go.dedis.ch/kyber/v3/pairing"
//"go.dedis.ch/onet/v3/log"
//"os"

func main() {
	//filePtr := flag.String("r", "", "roster.toml file")
	//flag.Parse()

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

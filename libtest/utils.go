package libtest

import (
	"flag"
	"github.com/dedis/protean/libclient"
	"github.com/dedis/protean/libexec"
	"github.com/dedis/protean/libstate"
	"github.com/dedis/protean/registry"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"os"
	"testing"
	"time"
)

var contractFile string
var fsmFile string
var dfuFile string

var testSuite = pairing.NewSuiteBn256()

func init() {
	flag.StringVar(&contractFile, "contract", "", "JSON file")
	flag.StringVar(&fsmFile, "fsm", "", "JSON file")
	flag.StringVar(&dfuFile, "dfu", "", "JSON file")
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func SetupRegistry(dfuFile *string, regRoster *onet.Roster,
	dfuRoster *onet.Roster) (*registry.Client, byzcoin.InstanceID,
	*byzcoin.Proof, error) {
	var id byzcoin.InstanceID
	dfuReg, err := libclient.ReadDFUJSON(dfuFile)
	if err != nil {
		return nil, id, nil, err
	}
	for k := range dfuReg.Units {
		//dfuReg.Units[k].Keys = roster.Publics()
		if k == "easyneff" || k == "threshold" || k == "easyrand" {
			dfuReg.Units[k].Keys = dfuRoster.ServicePublics(blscosi.ServiceName)
		} else if k == "codeexec" {
			dfuReg.Units[k].Keys = dfuRoster.ServicePublics(libexec.ServiceName)
		} else if k == "state" {
			dfuReg.Units[k].Keys = dfuRoster.ServicePublics(skipchain.ServiceName)
		} else {
			os.Exit(1)
		}
	}

	adminCl, byzID, err := registry.SetupByzcoin(regRoster, 1)
	if err != nil {
		return nil, id, nil, err
	}
	reply, err := adminCl.InitRegistry(dfuReg, 3)
	if err != nil {
		return nil, id, nil, err
	}
	pr, err := adminCl.Cl.WaitProof(reply.IID, 2*time.Second, nil)
	if err != nil {
		return nil, id, nil, err
	}

	bc := byzcoin.NewClient(byzID, *regRoster)
	cl := registry.NewClient(bc)
	return cl, reply.IID, pr, nil
}

func SetupStateUnit(roster *onet.Roster) (*libstate.AdminClient, error) {
	adminCl, byzID, err := libstate.SetupByzcoin(roster, 5)
	if err != nil {
		return nil, err
	}
	signer := darc.NewSignerEd25519(nil, nil)
	spawnDarc, err := adminCl.SpawnDarc(signer, adminCl.GMsg.GenesisDarc, 5)
	if err != nil {
		return nil, err
	}
	req := &libstate.InitUnitRequest{
		ByzID:  byzID,
		Roster: roster,
		Darc:   spawnDarc,
		Signer: signer,
	}
	_, err = adminCl.Cl.InitUnit(req)
	if err != nil {
		return nil, err
	}
	return adminCl, nil
}

func GenerateWriters(count int) []darc.Signer {
	writers := make([]darc.Signer, count)
	for i := 0; i < count; i++ {
		writers[i] = darc.NewSignerEd25519(nil, nil)
	}
	return writers
}

func GenerateReaders(count int) []darc.Signer {
	readers := make([]darc.Signer, count)
	for i := 0; i < count; i++ {
		readers[i] = darc.NewSignerEd25519(nil, nil)
	}
	return readers
}

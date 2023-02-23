package evoting

import (
	"flag"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3/log"
	"testing"
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
func Test_Voting(t *testing.T) {}

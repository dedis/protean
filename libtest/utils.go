package libtest

import (
	"github.com/dedis/protean/compiler"
	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3"
)

func InitCompilerUnit(local *onet.LocalTest, total int, roster *onet.Roster, hosts []*onet.Server, units []*sys.FunctionalUnit) error {
	compServices := local.GetServices(hosts[:total], compiler.GetServiceID())
	compNodes := make([]*compiler.Service, len(compServices))
	for i := 0; i < len(compServices); i++ {
		compNodes[i] = compServices[i].(*compiler.Service)
	}
	root := compNodes[0]
	initReply, err := root.InitUnit(&compiler.InitUnitRequest{Roster: roster, ScCfg: &sys.ScConfig{MHeight: 2, BHeight: 2}})
	if err != nil {
		return err
	}
	for _, n := range compNodes {
		_, err = n.StoreGenesis(&compiler.StoreGenesisRequest{Genesis: initReply.Genesis})
		if err != nil {
			return err
		}
	}
	_, err = root.CreateUnits(&compiler.CreateUnitsRequest{Units: units})
	return err
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

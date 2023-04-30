package main

import (
	"github.com/BurntSushi/toml"
	"github.com/dedis/protean/experiments/microbenchmarks/threshold/service"
	"github.com/dedis/protean/threshold/base"
	protean "github.com/dedis/protean/utils"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
)

type SimulationService struct {
	onet.SimulationBFTree
	NodeCount      int
	Threshold      int
	NumCiphertexts int
	IsRegular      bool
}

func init() {
	onet.SimulationRegister("ThresholdMicrobenchmark", NewMicrobenchmark)
}

func NewMicrobenchmark(config string) (onet.Simulation, error) {
	ss := &SimulationService{}
	_, err := toml.Decode(config, ss)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

func (s *SimulationService) Setup(dir string,
	hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (s *SimulationService) Node(config *onet.SimulationConfig) error {
	index, _ := config.Roster.Search(config.Server.ServerIdentity.GetID())
	if index < 0 {
		log.Fatal("Didn't find this node in roster")
	}
	log.Lvl3("Initializing node-index", index)
	return s.SimulationBFTree.Node(config)
}

func (s *SimulationService) runMicrobenchmark(config *onet.SimulationConfig) error {
	//dkgID := make([]byte, 32)
	//random.Bytes(dkgID, random.New())

	threshSvc := config.GetService(service.ServiceName).(*service.Service)

	dkgID := make([]byte, 32)
	random.Bytes(dkgID, random.New())
	dkgReply, _ := threshSvc.InitDKG(&service.InitDKGRequest{
		Roster:    config.Roster,
		Threshold: s.Threshold,
		ID:        dkgID,
	})

	for round := 0; round < s.Rounds; round++ {
		//dkgID = make([]byte, 32)
		//random.Bytes(dkgID, random.New())
		//mm := monitor.NewTimeMeasure("initdkg")
		//dkgReply, err := threshSvc.InitDKG(&service.InitDKGRequest{
		//	Roster:    config.Roster,
		//	Threshold: s.Threshold,
		//	ID:        dkgID,
		//})
		//if err != nil {
		//	log.Error(err)
		//	return err
		//}
		//mm.Record()
		_, ctexts := protean.GenerateMesgs(s.NumCiphertexts, "thresh_micro", dkgReply.Output.X)
		m := monitor.NewTimeMeasure("decrypt")
		req := &service.DecryptRequest{
			Roster:    config.Roster,
			Threshold: s.Threshold,
			IsRegular: s.IsRegular,
			ID:        dkgID,
			Input:     base.DecryptInput{ElGamalPairs: ctexts},
		}
		reply, err := threshSvc.Decrypt(req)
		if err != nil {
			log.Error(err)
			return err
		}
		for _, p := range reply.Output.Ps {
			_, err := p.Data()
			if err != nil {
				log.Error(err)
				return err
			}
			//if !bytes.Equal(pt, ptexts[i]) {
			//	log.Errorf("plaintext mismatch: %d", i)
			//}
			//log.Info("Plaintext is:", string(pt))
		}
		m.Record()
	}
	return nil
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	s.NodeCount = len(config.Roster.List)
	s.Threshold = s.NodeCount - (s.NodeCount-1)/3
	return s.runMicrobenchmark(config)

}

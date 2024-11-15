package main

import (
	"github.com/BurntSushi/toml"
	"github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/experiments/microbenchmarks/shuffle/service"
	protean "github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/util/key"
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
	onet.SimulationRegister("ShuffleMicrobenchmark", NewMicrobenchmark)
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
	kp := key.NewKeyPair(cothority.Suite)
	shufSvc := config.GetService(service.ServiceName).(*service.ShuffleSvc)

	_, dummyCts := protean.GenerateMesgs(2, "dummy_shuf", kp.Public)
	_, _ = shufSvc.DummyShuffle(&service.DummyRequest{
		Roster:    config.Roster,
		Threshold: s.Threshold,
		Input: base.ShuffleInput{
			Pairs: dummyCts,
			H:     kp.Public,
		},
		IsRegular: s.IsRegular,
	})

	for round := 0; round < s.Rounds; round++ {
		kp = key.NewKeyPair(cothority.Suite)
		_, ctexts := protean.GenerateMesgs(s.NumCiphertexts, "shuffle_micro", kp.Public)
		m := monitor.NewTimeMeasure("shuffle")
		reply, err := shufSvc.Shuffle(&service.ShuffleRequest{
			Roster:    config.Roster,
			Threshold: s.Threshold,
			Input: base.ShuffleInput{
				Pairs: ctexts,
				H:     kp.Public,
			},
			IsRegular: s.IsRegular,
		})
		if err != nil {
			log.Error(err)
			return err
		}
		m.Record()
		cs := reply.Proofs.Proofs[len(reply.Proofs.Proofs)-1].Pairs
		for _, p := range cs.Pairs {
			pt := protean.ElGamalDecrypt(kp.Private, p)
			_, err := pt.Data()
			if err != nil {
				log.Error(err)
				return err
			}
		}
	}
	return nil
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	s.NodeCount = len(config.Roster.List)
	s.Threshold = s.NodeCount - (s.NodeCount-1)/2
	log.Info("Threshold:", s.Threshold)
	return s.runMicrobenchmark(config)
}

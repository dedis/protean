package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/dedis/protean/experiments/commons"
	"github.com/dedis/protean/experiments/microbenchmarks/dummy/service"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
)

type SimulationService struct {
	onet.SimulationBFTree
	NumOutputStr string
	NumSizesStr  string
	NumOutputs   []int
	NumSizes     []int
	outputData   []map[string][]byte
}

func init() {
	onet.SimulationRegister("DummyMicrobenchmark", NewMicrobenchmark)
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

func (s *SimulationService) executeDummy(config *onet.SimulationConfig) error {
	var err error
	idx := 0
	dummySvc := config.GetService(service.ServiceName).(*service.DummySvc)
	for _, ns := range s.NumSizes {
		for _, no := range s.NumOutputs {
			log.Info("Starting dummy:", no, ns)
			for round := 0; round < s.Rounds; round++ {
				m := monitor.NewTimeMeasure(fmt.Sprintf("dummy_%d_%d", no, ns))
				req := service.DummyRequest{
					Roster:     config.Roster,
					OutputData: s.outputData[idx],
				}
				_, err = dummySvc.Dummy(&req)
				if err != nil {
					log.Error(err)
				}
				m.Record()
			}
			idx++
		}
	}
	return err
}

func (s *SimulationService) generateDummyData() {
	for _, ns := range s.NumSizes {
		for _, no := range s.NumOutputs {
			s.outputData = append(s.outputData, commons.PrepareData(no, ns))
		}
	}
}

func (s *SimulationService) runMicrobenchmark(config *onet.SimulationConfig) error {
	s.generateDummyData()
	log.Info("Starting executeDummy")
	err := s.executeDummy(config)
	return err
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	s.NumOutputs = commons.StringToIntSlice(s.NumOutputStr)
	s.NumSizes = commons.StringToIntSlice(s.NumSizesStr)
	err = s.runMicrobenchmark(config)
	return err
}

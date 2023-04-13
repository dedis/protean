package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/experiments/commons"
	"github.com/dedis/protean/experiments/microbenchmarks/dummy/service"
	"github.com/dedis/protean/libexec"
	execbase "github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/libstate"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
	"strconv"
	"strings"
)

type SimulationService struct {
	onet.SimulationBFTree
	ContractFile string
	FSMFile      string
	DFUFile      string
	BlockTime    int
	//NumOutputs   int
	//DataSize     int
	NumOutputStr string
	NumSizesStr  string
	NumOutputs   []int
	NumSizes     []int

	// internal structs
	byzID       skipchain.SkipBlockID
	stRoster    *onet.Roster
	execRoster  *onet.Roster
	dummyRoster *onet.Roster
	stCl        *libstate.Client
	execCl      *libexec.Client
	receipts    map[string]*core.OpcodeReceipt
	outputData  []map[string][]byte

	threshMap   map[string]int
	rdata       *execbase.ByzData
	CID         byzcoin.InstanceID
	contractGen *skipchain.SkipBlock
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

func (s *SimulationService) initDFUs() error {
	s.execCl = libexec.NewClient(s.execRoster)
	_, err := s.execCl.InitUnit(s.threshMap[execbase.UID])
	if err != nil {
		log.Errorf("initializing execution unit: %v", err)
		return err
	}
	// Setup the state unit
	s.byzID, err = commons.SetupStateUnit(s.stRoster, s.BlockTime)
	if err != nil {
		log.Error(err)
	}
	return err
}

//
//func (s *SimulationService) executeDummy(config *onet.SimulationConfig) error {
//	var err error
//	dummySvc := config.GetService(service.ServiceName).(*service.DummySvc)
//
//	log.Info("Starting dummy:", s.NumOutputs, s.DataSize)
//	for round := 0; round < s.Rounds; round++ {
//		m := monitor.NewTimeMeasure("dummy")
//		req := service.DummyRequest{
//			Roster:     s.dummyRoster,
//			OutputData: commons.PrepareData(s.NumOutputs, s.DataSize),
//		}
//		_, err = dummySvc.Dummy(&req)
//		if err != nil {
//			log.Error(err)
//		}
//		m.Record()
//	}
//
//	return err
//}

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
					Roster:     s.dummyRoster,
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

func (s *SimulationService) stringSliceToIntSlice() {
	numOutputsSlice := strings.Split(s.NumOutputStr, ";")
	for _, n := range numOutputsSlice {
		numOutput, _ := strconv.Atoi(n)
		s.NumOutputs = append(s.NumOutputs, numOutput)
	}
	numSizesSlice := strings.Split(s.NumSizesStr, ";")
	for _, n := range numSizesSlice {
		numSizes, _ := strconv.Atoi(n)
		s.NumSizes = append(s.NumSizes, numSizes)
	}
	fmt.Println(s.NumOutputs)
	fmt.Println(s.NumSizes)
}

func (s *SimulationService) runMicrobenchmark(config *onet.SimulationConfig) error {
	//err := s.initDFUs()
	//if err != nil {
	//	return err
	//}
	s.stringSliceToIntSlice()
	s.generateDummyData()
	log.Info("Starting executeDummy")
	err := s.executeDummy(config)
	return err
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	//regRoster := onet.NewRoster(config.Roster.List[0:4])
	//s.stRoster = onet.NewRoster(config.Roster.List[0:4])
	//s.execRoster = onet.NewRoster(config.Roster.List[0:4])
	//s.dummyRoster = onet.NewRoster(config.Roster.List[4:])
	//s.dummyRoster.List[0] = config.Roster.List[0]
	//
	//keyMap := make(map[string][]kyber.Point)
	//keyMap[service.UID] = s.dummyRoster.ServicePublics(service.ServiceName)
	//keyMap[statebase.UID] = s.stRoster.ServicePublics(skipchain.ServiceName)
	//keyMap[execbase.UID] = s.execRoster.ServicePublics(libexec.ServiceName)
	//s.rdata, s.threshMap, err = commons.SetupRegistry(regRoster, &s.DFUFile,
	//	keyMap, s.BlockTime)
	//if err != nil {
	//	log.Error(err)
	//}
	s.dummyRoster = config.Roster
	err = s.runMicrobenchmark(config)
	return err
}

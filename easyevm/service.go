package easyevm

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"golang.org/x/xerrors"
)

var easyevmID onet.ServiceID

// ServiceName is the name of the EasyEVM service
const ServiceName = "EasyEVMService"

func init() {
	// Ethereum starts goroutines for caching transactions, and never
	// terminates them. Here we ignore the resulting "goroutine leak" error.
	log.AddUserUninterestingGoroutine(
		"go-ethereum/core.(*txSenderCacher).cache")

	var err error
	easyevmID, err = onet.RegisterNewService(ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessages(ExecEVM{}, ExecEVMReply{})
}

// Service holds the Onet serivce
type Service struct {
	*onet.ServiceProcessor
}

// ExecEVM provides a stateless service function that allows one to execute a
// solidity smart contract on the Ethereum virtual machine. This service is
// naive in the sense that is requires the entire database to be passed as
// argument, and return the entire updated database. To get the state of a smart
// contract, one doesn't need to call this sevice, but can use the "CallEVM"
// function in mod.go.
//
// This service uses the "EasyEVMProtocol", which asks every node to execute the
// smart contract and checks that every node has the same output.
//
// Note that most of the code is heavily borrowed from the BEVM implementation
// in cothority/bevm.
func (s *Service) ExecEVM(req *ExecEVM) (*ExecEVMReply, error) {
	tree := req.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	if tree == nil {
		return nil, xerrors.Errorf("failed to create tree")
	}

	pi, err := s.CreateProtocol(ProtocolName, tree)
	if err != nil {
		return nil, xerrors.Errorf("failed to create protocol: %v", err)
	}

	evmProtocol := pi.(*easyevmProtocol)
	evmProtocol.db = req.db
	evmProtocol.txJSON = req.txJSON
	evmProtocol.timestamp = int(time.Now().Unix())
	evmProtocol.root = req.root

	err = pi.Start()
	if err != nil {
		return nil, xerrors.Errorf("failed to start protocol: %v", err)
	}

	execResult := <-evmProtocol.ResultChan

	resp := &ExecEVMReply{
		db:          execResult.DB,
		receiptJSON: execResult.ReceiptJSON,
		root:        execResult.Root,
	}

	return resp, nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}

	err := s.RegisterHandlers(s.ExecEVM)
	if err != nil {
		return nil, xerrors.Errorf("failed to register handler: %v", err)
	}

	return s, nil
}

// ExecEVM holds the arguments of the ExecEVM service's function
type ExecEVM struct {
	Roster *onet.Roster
	txJSON []byte
	db     map[string][]byte
	root   *common.Hash
}

// ExecEVMReply is the response from the execution of the ExecEVM service's
// function
type ExecEVMReply struct {
	db          map[string][]byte
	receiptJSON []byte
	root        *common.Hash
}

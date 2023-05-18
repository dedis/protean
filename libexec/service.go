package libexec

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/libexec/protocol/execute"
	"github.com/dedis/protean/libexec/protocol/inittxn"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

const ServiceName = "libexec_svc"

var execID onet.ServiceID

var suite = suites.MustFind("bn256.adapter").(*pairing.SuiteBn256)

func init() {
	var err error
	execID, err = onet.RegisterNewServiceWithSuite(ServiceName, suite,
		newService)
	network.RegisterMessages(&InitUnit{}, &InitUnitReply{},
		&InitTransaction{}, &InitTransactionReply{}, &Execute{}, &ExecuteReply{})
	if err != nil {
		panic(err)
	}
}

type Service struct {
	*onet.ServiceProcessor
	suite     pairing.SuiteBn256
	roster    *onet.Roster
	threshold int
}

func (s *Service) InitUnit(req *InitUnit) (*InitUnitReply, error) {
	s.roster = req.Roster
	s.threshold = req.Threshold
	return &InitUnitReply{}, nil
}

func (s *Service) InitTransaction(req *InitTransaction) (*InitTransactionReply, error) {
	nodeCount := len(s.roster.List)
	//threshold := nodeCount - (nodeCount-1)/3
	tree := s.roster.GenerateNaryTreeWithRoot(nodeCount-1, s.ServerIdentity())
	pi, err := s.CreateProtocol(inittxn.ProtoName, tree)
	if err != nil {
		return nil, xerrors.Errorf("failed to create protocol: %v", err)
	}
	proto := pi.(*inittxn.InitTxn)
	proto.KP = s.getKeyPair()
	proto.Publics = s.roster.ServicePublics(ServiceName)
	proto.Threshold = s.threshold
	proto.Input = &req.Input
	proto.GeneratePlan = s.generateExecutionPlan
	err = proto.Start()
	if err != nil {
		return nil, xerrors.Errorf("failed to start the protocol: %v", err)
	}
	if !<-proto.Executed {
		return nil, xerrors.New("couldn't generate the execution plan")
	}
	//proto.Plan.Sig = proto.FinalSignature
	proto.Plan.Sig = proto.FinalSignature
	return &InitTransactionReply{
		Plan: *proto.Plan,
	}, nil
}

func (s *Service) Execute(req *Execute) (*ExecuteReply, error) {
	nodeCount := len(s.roster.List)
	//threshold := nodeCount - (nodeCount-1)/3
	tree := s.roster.GenerateNaryTreeWithRoot(nodeCount-1, s.ServerIdentity())
	pi, err := s.CreateProtocol(execute.ProtoName, tree)
	if err != nil {
		return nil, xerrors.Errorf("failed to create the protocol: %v", err)
	}
	proto := pi.(*execute.Execute)
	proto.Input = &req.Input
	proto.ExecReq = &req.ExecReq
	proto.KP = s.getKeyPair()
	proto.Publics = s.roster.ServicePublics(ServiceName)
	proto.Threshold = s.threshold
	err = proto.Start()
	if err != nil {
		return nil, xerrors.Errorf("failed to start the protocol: %v", err)
	}
	if !<-proto.Executed {
		return nil, xerrors.New("couldn't execute application code")
	}
	return &ExecuteReply{Output: *proto.Output,
		InputReceipts:  proto.InputReceipts,
		OutputReceipts: proto.OutputReceipts}, nil
}

func (s *Service) getKeyPair() *key.Pair {
	return &key.Pair{
		Public:  s.ServerIdentity().ServicePublic(ServiceName),
		Private: s.ServerIdentity().ServicePrivate(ServiceName),
	}
}

func (s *Service) generateExecutionPlan(input *base.InitTxnInput) (*core.ExecutionPlan, error) {
	registry, raw, header, err := verifyInitTxn(input)
	if err != nil {
		return nil, xerrors.Errorf("verification error -- %v", err)
	}
	root := input.CData.Proof.InclusionProof.GetRoot()
	txn, ok := raw.Contract.Workflows[input.WfName].Txns[input.TxnName]
	if !ok {
		return nil, xerrors.Errorf("cannot find txn %s in workflow %s", input.TxnName, input.WfName)
	}
	dfuData := make(map[string]*core.DFUIdentity)
	for _, opcode := range txn.Opcodes {
		dfu, ok := registry.Units[opcode.DFUID]
		if !ok {
			return nil, xerrors.Errorf("cannot find dfu information for dfu %s", opcode.DFUID)
		}
		_, ok = dfuData[opcode.DFUID]
		if !ok {
			dfuID := core.DFUIdentity{
				Threshold: dfu.Threshold,
				Keys:      dfu.Keys,
			}
			dfuData[opcode.DFUID] = &dfuID
		}
	}
	plan := &core.ExecutionPlan{
		CID:       header.CID.Slice(),
		StateRoot: root,
		CodeHash:  header.CodeHash,
		WfName:    input.WfName,
		TxnName:   input.TxnName,
		Txn:       txn,
		DFUData:   dfuData,
	}
	return plan, nil
}

func verifyInitTxn(input *base.InitTxnInput) (*core.DFURegistry, *core.ContractRaw, *core.ContractHeader, error) {
	// Verify Byzcoin proofs
	err := input.RData.Proof.VerifyFromBlock(input.RData.Genesis)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot verify byzcoin proof ("+
			"registry): %v", err)
	}
	err = input.CData.Proof.VerifyFromBlock(input.CData.Genesis)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot verify byzcoin proof (contract): %v", err)
	}
	// Get registry data
	v, _, _, err := input.RData.Proof.Get(input.RData.IID.Slice())
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot get data from registry proof: %v", err)
	}
	store := core.Storage{}
	err = protobuf.Decode(v, &store)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot decode registry contract storage: %v", err)
	}
	registry := core.DFURegistry{}
	err = protobuf.Decode(store.Store[0].Value, &registry)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot decode registry data: %v", err)
	}
	// Get contract header
	v, _, _, err = input.CData.Proof.Get(input.CData.IID.Slice())
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot get data from state proof: %v", err)
	}
	store = core.Storage{}
	err = protobuf.Decode(v, &store)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot decode state contract storage: %v", err)
	}
	raw := core.ContractRaw{}
	err = protobuf.Decode(store.Store[0].Value, &raw)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot decode raw contract: %v", err)
	}
	header := core.ContractHeader{}
	err = protobuf.Decode(store.Store[1].Value, &header)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot decode contract header: %v", err)
	}
	// Check if CIDs match
	if !(raw.CID.Equal(input.CData.IID) && header.CID.Equal(input.CData.IID)) {
		return nil, nil, nil, xerrors.New("contract IDs do not match")
	}
	// Check that this txn can be executed in the curr_state
	transition, ok := raw.FSM.Transitions[input.TxnName]
	if !ok {
		return nil, nil, nil, xerrors.New("invalid txn name")
	}
	if transition.From != header.CurrState {
		return nil, nil, nil, xerrors.Errorf("cannot execute txn %s in curr_state %s",
			input.TxnName, header.CurrState)
	}
	return &registry, &raw, &header, nil
}

func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	switch tn.ProtocolName() {
	case inittxn.ProtoName:
		pi, err := inittxn.NewInitTxn(tn)
		if err != nil {
			return nil, xerrors.Errorf("creating protocol instance: %v", err)
		}
		proto := pi.(*inittxn.InitTxn)
		proto.KP = s.getKeyPair()
		proto.GeneratePlan = s.generateExecutionPlan
		return proto, nil
	case execute.ProtoName:
		pi, err := execute.NewExecute(tn)
		if err != nil {
			return nil, xerrors.Errorf("creating protocol instance: %v", err)
		}
		proto := pi.(*execute.Execute)
		proto.KP = s.getKeyPair()
		return proto, nil
	}
	return nil, nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		suite:            *suite,
	}
	if err := s.RegisterHandlers(s.InitUnit, s.InitTransaction, s.Execute); err != nil {
		return nil, xerrors.New("couldn't register messages")
	}
	return s, nil
}

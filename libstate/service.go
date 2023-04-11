package libstate

import (
	"encoding/hex"
	"github.com/dedis/protean/contracts"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libstate/base"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

var stateID onet.ServiceID

const ServiceName = "StateService"

var suite = suites.MustFind("bn256.adapter").(*pairing.SuiteBn256)

func init() {
	var err error
	stateID, err = onet.RegisterNewServiceWithSuite(ServiceName, suite, newService)
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&InitContractRequest{}, &InitContractReply{}, &GetStateRequest{},
		&GetStateReply{}, &UpdateStateRequest{}, &UpdateStateReply{},
		&DummyRequest{}, &DummyReply{}, &storage{})
	if err != nil {
		panic(err)
	}
	err = byzcoin.RegisterGlobalContract(contracts.ContractKeyValueID, contracts.ContractKeyValueFromBytes)
}

type Service struct {
	*onet.ServiceProcessor
	storage *storage
	suite   pairing.SuiteBn256
	bc      *byzcoin.Client
	byzID   skipchain.SkipBlockID
	signer  darc.Signer
	darc    *darc.Darc
	ctr     uint64
	roster  *onet.Roster
}

func (s *Service) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	s.bc = nil
	s.byzID = req.ByzID
	s.roster = req.Roster
	s.signer = req.Signer
	s.darc = req.Darc
	s.ctr = uint64(1)
	return &InitUnitReply{}, nil
}

func (s *Service) InitContract(req *InitContractRequest) (*InitContractReply, error) {
	if s.bc == nil {
		s.bc = byzcoin.NewClient(s.byzID, *s.roster)
	}
	rawBuf, err := protobuf.Encode(req.Raw)
	if err != nil {
		return nil, xerrors.Errorf("encoding raw contract: %v", err)
	}
	hdrBuf, err := protobuf.Encode(req.Header)
	if err != nil {
		return nil, xerrors.Errorf("encoding contract header: %v", err)
	}
	args := byzcoin.Arguments{{Name: "raw", Value: rawBuf},
		{Name: "header", Value: hdrBuf}}
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: byzcoin.NewInstanceID(s.darc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: contracts.ContractKeyValueID,
				Args:       args,
			},
			SignerCounter: []uint64{s.ctr},
		})
	err = ctx.FillSignersAndSignWith(s.signer)
	if err != nil {
		return nil, xerrors.Errorf("signing transaction: %v", err)
	}
	cid := ctx.Instructions[0].DeriveID("")
	_, err = s.bc.AddTransactionAndWait(ctx, req.Wait)
	if err != nil {
		return nil, xerrors.Errorf("adding transaction: %v", err)
	}
	s.ctr++
	// Store CID in header
	req.Raw.CID = cid
	req.Header.CID = cid
	rawBuf, err = protobuf.Encode(req.Raw)
	if err != nil {
		return nil, xerrors.Errorf("encoding raw contract: %v", err)
	}
	hdrBuf, err = protobuf.Encode(req.Header)
	if err != nil {
		return nil, xerrors.Errorf("encoding contract header: %v", err)
	}
	args[0].Value = rawBuf
	args[1].Value = hdrBuf
	if req.InitArgs != nil {
		args = append(args, req.InitArgs...)
	}
	ctx = byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: cid,
			Invoke: &byzcoin.Invoke{
				ContractID: contracts.ContractKeyValueID,
				Command:    "init_contract",
				Args:       args,
			},
			SignerCounter: []uint64{s.ctr},
		})
	err = ctx.FillSignersAndSignWith(s.signer)
	if err != nil {
		return nil, xerrors.Errorf("adding update transaction: %v", err)
	}
	reply := &InitContractReply{CID: cid}
	reply.TxResp, err = s.bc.AddTransactionAndWait(ctx, req.Wait)
	if err != nil {
		return nil, xerrors.Errorf("adding transaction: %v", err)
	}
	s.ctr++
	return reply, err
}

func (s *Service) GetState(req *GetStateRequest) (*GetStateReply, error) {
	if s.bc == nil {
		s.bc = byzcoin.NewClient(s.byzID, *s.roster)
	}
	pr, err := s.bc.GetProof(req.CID.Slice())
	if err != nil {
		return nil, xerrors.Errorf("failed to get proof from byzcoin: %v", err)
	}
	proof := core.StateProof{Proof: &pr.Proof, Genesis: s.bc.Genesis}
	return &GetStateReply{Proof: proof}, nil
}

func (s *Service) UpdateState(req *UpdateStateRequest) (*UpdateStateReply, error) {
	root := hex.EncodeToString(req.ExecReq.EP.StateRoot)
	s.storage.Lock()
	_, ok := s.storage.CurrState[root]
	if ok {
		s.storage.Unlock()
		log.Error("another update state is in progress")
		return nil, xerrors.New("another update state request is in progress")
	}
	s.storage.CurrState[root] = true
	s.storage.Unlock()
	r := contracts.Request{ExecReq: &req.ExecReq,
		InReceipts: req.InputReceipts, UID: base.UID,
		OpcodeName: base.UPDATE_STATE}
	reqBuf, err := protobuf.Encode(&r)
	if err != nil {
		return nil, err
	}
	req.Input.Args = append(req.Input.Args, byzcoin.Argument{Name: "request",
		Value: reqBuf})
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: byzcoin.NewInstanceID(req.ExecReq.EP.CID),
			Invoke: &byzcoin.Invoke{
				ContractID: contracts.ContractKeyValueID,
				Command:    "update",
				Args:       req.Input.Args,
			},
			SignerCounter: []uint64{s.ctr},
		})
	err = ctx.FillSignersAndSignWith(s.signer)
	if err != nil {
		return nil, xerrors.Errorf("signing transaction: %v", err)
	}
	txResp, err := s.bc.AddTransactionAndWait(ctx, req.Wait)
	if err != nil {
		return nil, err
	}
	s.ctr++
	return &UpdateStateReply{TxResp: txResp}, nil
}

func (s *Service) DummyUpdate(req *DummyRequest) (*DummyReply, error) {
	if s.bc == nil {
		s.bc = byzcoin.NewClient(s.byzID, *s.roster)
	}
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: req.CID,
			Invoke: &byzcoin.Invoke{
				ContractID: contracts.ContractKeyValueID,
				Command:    "dummy",
				Args:       req.Input.Args,
			},
			SignerCounter: []uint64{s.ctr},
		})
	err := ctx.FillSignersAndSignWith(s.signer)
	if err != nil {
		return nil, xerrors.Errorf("signing transaction: %v", err)
	}
	txResp, err := s.bc.AddTransactionAndWait(ctx, req.Wait)
	if err != nil {
		return nil, err
	}
	s.ctr++
	return &DummyReply{TxResp: txResp}, nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		suite:            *suite,
	}
	if err := s.RegisterHandlers(s.InitUnit, s.InitContract, s.GetState,
		s.UpdateState, s.DummyUpdate); err != nil {
		return nil, xerrors.New("couldn't register messages")
	}
	if err := s.tryLoad(); err != nil {
		log.Error(err)
		return nil, xerrors.Errorf("loading configuration: %v", err)
	}
	return s, nil
}

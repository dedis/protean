package libstate

import (
	"bytes"
	"encoding/hex"
	"github.com/dedis/protean/contracts"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libstate/base"
	"github.com/dedis/protean/libstate/protocol/verify"
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
		&GetStateReply{}, &storage{})
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
				Command:    "update",
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
		log.Info("In GS nil")
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
		return nil, xerrors.New("another update state request is in progress")
	}
	s.storage.CurrState[root] = true
	s.storage.Unlock()
	// Verify the execution request
	err := s.runVerification(req)
	if err != nil {
		return nil, err
	}
	if s.bc == nil {
		s.bc = byzcoin.NewClient(s.byzID, *s.roster)
	}
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

func (s *Service) runVerification(req *UpdateStateRequest) error {
	nodeCount := len(s.roster.List)
	threshold := nodeCount - (nodeCount-1)/3
	tree := s.roster.GenerateNaryTreeWithRoot(nodeCount-1, s.ServerIdentity())
	pi, err := s.CreateProtocol(verify.ProtoName, tree)
	if err != nil {
		return xerrors.Errorf("failed to create the protocol: %v", err)
	}
	proto := pi.(*verify.Verify)
	proto.Input = &req.Input
	proto.ExecReq = &req.ExecReq
	proto.InputHashes = req.Input.PrepareHashes()
	proto.VerifyFn = s.verifyUpdate
	proto.Threshold = threshold
	err = proto.Start()
	if err != nil {
		return xerrors.Errorf("failed to start the protocol: %v", err)
	}
	if !<-proto.Verified {
		return xerrors.New("failed to verify the execution request")
	}
	return nil
}

func (s *Service) verifyUpdate(input *base.UpdateInput, req *core.ExecutionRequest) bool {
	err := func() error {
		if s.bc == nil {
			s.bc = byzcoin.NewClient(s.byzID, *s.roster)
		}
		pr, err := s.bc.GetProof(req.EP.CID)
		if err != nil {
			return xerrors.Errorf("failed to get proof from byzcoin: %v", err)
		}
		// 1) Check if Merkle roots match
		if !bytes.Equal(pr.Proof.InclusionProof.GetRoot(), req.EP.StateRoot) {
			return xerrors.New("merkle roots do not match")
		}
		// Get contract header
		v, _, _, err := pr.Proof.Get(req.EP.CID)
		if err != nil {
			return xerrors.Errorf("failed to retrieve key/value pairs: %v", err)
		}
		kvStore := &contracts.Storage{}
		err = protobuf.Decode(v, kvStore)
		if err != nil {
			return xerrors.Errorf("failed to get contract storage: %v", err)
		}
		hdr := &core.ContractHeader{}
		err = protobuf.Decode(kvStore.Store[1].Value, hdr)
		if err != nil {
			return xerrors.Errorf("failed to get contract header: %v", err)
		}
		// 2) Check that the CIDs match the value in the contract header
		if !bytes.Equal(req.EP.CID, hdr.CID[:]) {
			return xerrors.New("inconsistent CID value")
		}
		// 3) Check that writeset is generated by the correct code
		if !bytes.Equal(req.EP.CodeHash, hdr.CodeHash) {
			return xerrors.New("code hashes do no match")
		}
		return nil
	}()
	if err != nil {
		log.Errorf("cannot verify update state request: %v", err)
		return false
	}
	return true
}

func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	switch tn.ProtocolName() {
	case verify.ProtoName:
		pi, err := verify.NewUpdateVerify(tn)
		if err != nil {
			return nil, xerrors.Errorf("creating protocol instance: %v", err)
		}
		proto := pi.(*verify.Verify)
		proto.VerifyFn = s.verifyUpdate
		return proto, nil
	}
	return nil, nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		suite:            *suite,
	}
	if err := s.RegisterHandlers(s.InitUnit, s.InitContract, s.GetState,
		s.UpdateState); err != nil {
		return nil, xerrors.New("couldn't register messages")
	}
	if err := s.tryLoad(); err != nil {
		log.Error(err)
		return nil, xerrors.Errorf("loading configuration: %v", err)
	}
	return s, nil
}

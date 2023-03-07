package randlottery

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

func JoinLottery(genInput *base.GenericInput) (*base.GenericOutput, error) {
	input, ok := genInput.I.(JoinInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	ticket := input.Ticket
	pkHash, err := utils.HashPoint(ticket.Key)
	if err != nil {
		return nil, xerrors.Errorf("couldn't calculate the hash of pk: %v",
			err)
	}
	err = schnorr.Verify(cothority.Suite, ticket.Key, pkHash, ticket.Sig)
	if err != nil {
		return nil, xerrors.Errorf("couldn't verify signature: %v", err)
	}
	kvDict, ok := genInput.KVInput["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	tickets, err := getTickets(&kvDict)
	if err != nil {
		return nil, err
	}
	tickets.Data = append(tickets.Data, ticket)
	buf, err := protobuf.Encode(tickets)
	//log.Infof("Tickets size: %d", len(buf))
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode tickets: %v", err)
	}
	args := byzcoin.Arguments{{Name: "tickets", Value: buf}}
	return &base.GenericOutput{O: JoinOutput{WS: args}}, nil
}

func CloseLottery(genInput *base.GenericInput) (*base.GenericOutput, error) {
	input, ok := genInput.I.(CloseInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	// Check that the barrier point is passed
	if input.BlkHeight < input.Barrier {
		return nil, xerrors.New("barrier point is not reached yet")
	}
	// Get header
	kvDict, ok := genInput.KVInput["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	hdr, err := getHeader(&kvDict)
	if err != nil {
		return nil, err
	}
	hdr.CurrState = "lottery_closed"
	buf, err := protobuf.Encode(hdr)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode header: %v", err)
	}
	args := byzcoin.Arguments{{Name: "header", Value: buf}}
	return &base.GenericOutput{O: CloseOutput{WS: args}}, nil
}

func FinalizeLottery(genInput *base.GenericInput) (*base.GenericOutput, error) {
	input, ok := genInput.I.(FinalizeInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	// Check that the round values match
	if input.Round != input.Randomness.Round {
		return nil, xerrors.New("invalid round value")
	}
	// Verify randomness
	suite := pairing.NewSuiteBn256()
	err := bls.Verify(suite, input.Randomness.Public, input.Randomness.Prev,
		input.Randomness.Value)
	if err != nil {
		return nil, xerrors.Errorf("couldn't verify randomness: %v", err)
	}
	// Derive random integer
	h := sha256.New()
	h.Write(input.Randomness.Value)
	randBytes := h.Sum(nil)
	rand := binary.LittleEndian.Uint64(randBytes)
	// Get tickets
	kvDict, ok := genInput.KVInput["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	tickets, err := getTickets(&kvDict)
	if err != nil {
		return nil, err
	}
	// Find winner
	winnerIdx := rand % uint64(len(tickets.Data))
	winner := Winner{
		Index: int(winnerIdx),
		Key:   tickets.Data[winnerIdx].Key,
	}
	log.Info("Winner index:", winnerIdx, winner.Key.String())
	// Get header
	hdr, err := getHeader(&kvDict)
	if err != nil {
		return nil, err
	}
	hdr.CurrState = "lottery_finalized"
	hdrBuf, err := protobuf.Encode(hdr)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode header: %v", err)
	}
	// Prepare write set
	randBuf, err := protobuf.Encode(&input.Randomness)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode randomness: %v", err)
	}
	//log.Infof("randomness size: %d", len(randBuf))
	winnerBuf, err := protobuf.Encode(&winner)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode winner data: %v", err)
	}
	args := byzcoin.Arguments{
		{Name: "header", Value: hdrBuf},
		{Name: "randomness", Value: randBuf},
		{Name: "winner", Value: winnerBuf},
	}
	return &base.GenericOutput{O: FinalizeOutput{WS: args}}, nil
}

func getHeader(kvDict *core.KVDict) (*core.ContractHeader, error) {
	buf, ok := kvDict.Data["header"]
	if !ok {
		return nil, xerrors.New("missing key: header")
	}
	hdr := &core.ContractHeader{}
	err := protobuf.Decode(buf, hdr)
	if err != nil {
		return nil, xerrors.Errorf("couldn't decode header: %v", err)
	}
	return hdr, nil
}

func getTickets(kvDict *core.KVDict) (*Tickets, error) {
	buf, ok := kvDict.Data["tickets"]
	if !ok {
		return nil, xerrors.New("missing key: tickets")
	}
	tickets := &Tickets{}
	err := protobuf.Decode(buf, tickets)
	if err != nil {
		return nil, xerrors.Errorf("couldn't decode tickets: %v", err)
	}
	return tickets, nil
}

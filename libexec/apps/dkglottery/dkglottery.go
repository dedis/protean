package dkglottery

import (
	"encoding/binary"

	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	threshold "github.com/dedis/protean/threshold/base"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

func Setup(genInput *base.GenericInput) (*base.GenericOutput, error) {
	input, ok := genInput.I.(SetupInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	kvDict, ok := genInput.KVInput["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	hdr, err := getHeader(&kvDict)
	if err != nil {
		return nil, err
	}
	hdr.CurrState = "lottery_open"
	hdrBuf, err := protobuf.Encode(hdr)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode header: %v", err)
	}
	pkBuf, err := input.Pk.MarshalBinary()
	if err != nil {
		return nil, xerrors.Errorf("marshaling public key: %v", err)
	}
	args := byzcoin.Arguments{
		{Name: "header", Value: hdrBuf},
		{Name: "pk", Value: pkBuf},
	}
	return &base.GenericOutput{O: SetupOutput{WS: args}}, nil
}

func JoinLottery(genInput *base.GenericInput) (*base.GenericOutput, error) {
	input, ok := genInput.I.(JoinInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	kvDict, ok := genInput.KVInput["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	tickets, err := getTickets(&kvDict)
	if err != nil {
		return nil, err
	}
	tickets.Data.Pairs = append(tickets.Data.Pairs, input.Ticket.Data)
	buf, err := protobuf.Encode(tickets)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode tickets: %v", err)
	}
	//log.Infof("enc_tickets size: %d", len(buf))
	args := byzcoin.Arguments{{Name: "enc_tickets", Value: buf}}
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

func PrepareDecrypt(genInput *base.GenericInput) (*base.GenericOutput, error) {
	kvDict, ok := genInput.KVInput["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	tickets, err := getTickets(&kvDict)
	if err != nil {
		return nil, err
	}
	input := threshold.DecryptInput{ElGamalPairs: tickets.Data}
	return &base.GenericOutput{O: PrepDecOutput{Input: input}}, nil
}

func FinalizeLottery(genInput *base.GenericInput) (*base.GenericOutput, error) {
	input, ok := genInput.I.(FinalizeInput)
	if !ok {
		return nil, xerrors.New("missing input")
	}
	pdata := make([][]byte, len(input.Ps))
	for i, p := range input.Ps {
		msg, err := p.Data()
		if err != nil {
			return nil, xerrors.Errorf("couldn't recover plaintext: %v", err)
		}
		pdata[i] = msg
	}
	randBytes := generateRandomness(pdata)
	rand := binary.LittleEndian.Uint64(randBytes)
	winnerIdx := rand % uint64(len(pdata))
	winner := Winner{
		Index:  int(winnerIdx),
		Ticket: pdata[winnerIdx],
	}
	log.Info("Winner is:", winner.Index, winner.Ticket)
	// Prepare write set
	kvDict, ok := genInput.KVInput["readset"]
	if !ok {
		return nil, xerrors.New("missing keyvalue data")
	}
	hdr, err := getHeader(&kvDict)
	if err != nil {
		return nil, err
	}
	hdr.CurrState = "lottery_finalized"
	hdrBuf, err := protobuf.Encode(hdr)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode header: %v", err)
	}
	decTickets := DecTickets{Data: pdata}
	dtBuf, err := protobuf.Encode(&decTickets)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode decrypted tickets: %v", err)
	}
	winnerBuf, err := protobuf.Encode(&winner)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode winner data: %v", err)
	}
	args := byzcoin.Arguments{
		{Name: "header", Value: hdrBuf},
		{Name: "dec_tickets", Value: dtBuf},
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

func getTickets(kvDict *core.KVDict) (*EncTickets, error) {
	buf, ok := kvDict.Data["enc_tickets"]
	if !ok {
		return nil, xerrors.New("missing key: enc_tickets")
	}
	tickets := &EncTickets{}
	err := protobuf.Decode(buf, tickets)
	if err != nil {
		return nil, xerrors.Errorf("couldn't decode tickets: %v", err)
	}
	return tickets, nil
}

func generateRandomness(data [][]byte) []byte {
	sz := len(data[0])
	rand := make([]byte, sz)
	copy(rand, data[0])
	for i := 1; i < len(data); i++ {
		for j := 0; j < sz; j++ {
			rand[j] = rand[j] ^ data[i][j]
		}
	}
	return rand
}

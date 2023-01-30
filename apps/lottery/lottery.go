package lottery

import (
	"crypto/sha256"
	"encoding/binary"
	"github.com/dedis/protean/contracts"
	"github.com/dedis/protean/libexec/commons"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

func JoinLottery(inputs []commons.Input) ([]commons.Output, error) {
	//ticket, ok := inputs[0].I.(Ticket)
	//if !ok {
	//	return nil, xerrors.Errorf("couldn't find the ticket input")
	//}

	input, ok := inputs[0].I.(JoinLotteryInput)
	if !ok {
		return nil, xerrors.Errorf("couldn't find the join lottery input")
	}
	ticket := input.Ticket
	h := sha256.New()
	pkBuf, err := input.Ticket.Key.MarshalBinary()
	if err != nil {
		return nil, xerrors.Errorf("cannot decode public key: %v", err)
	}
	h.Write(pkBuf)
	pkBuf = h.Sum(nil)
	err = schnorr.Verify(cothority.Suite, ticket.Key, pkBuf, ticket.Sig)
	if err != nil {
		return nil, xerrors.Errorf("cannot verify signature: %v", err)
	}

	//kvData, ok := inputs[1].I.(KVInputData)
	//if !ok {
	//	return nil, xerrors.Errorf("couldn't find the kv data input")
	//}

	kvData := input.KVData
	//TODO: verify proof using VerifyFromBlock
	//TODO: get CID from execution request
	cid := []byte("CID")
	v, _, _, err := kvData.StateProof.Proof.Get(cid)
	if err != nil {
		return nil, xerrors.Errorf("couldn't get data from state proof: %v", err)
	}
	store := contracts.Storage{}
	err = protobuf.Decode(v, &store)
	if err != nil {
		return nil, xerrors.Errorf("couldn't decode state contract storage: %v", err)
	}
	idx := -1
	for i := 1; i < len(store.Store); i++ {
		if store.Store[i].Key == "tickets" {
			idx = i
			break
		}
	}
	tickets := Tickets{}
	if idx > 1 {
		// tickets already exists so we need to decode first
		val := store.Store[idx].Value
		err = protobuf.Decode(val, &tickets)
		if err != nil {
			return nil, xerrors.Errorf("couldn't decode tickets: %v", err)
		}
	}
	tickets.Data = append(tickets.Data, ticket)
	kvBuf, err := protobuf.Encode(&tickets)
	if err != nil {
		return nil, xerrors.Errorf("couldn't encode tickets: %v", err)
	}
	kv := byzcoin.Arguments{{Name: "tickets", Value: kvBuf}}
	outputs := make([]commons.Output, 1)
	outputs[0].O = KVOutputData{Args: kv}
	return outputs, nil
}

func RevealWinner(inputs []commons.Input) ([]commons.Output, error) {
	//randomness, ok := inputs[0].I.(RandomnessInput)
	input, ok := inputs[0].I.(RevealWinnerInput)
	if !ok {
		return nil, xerrors.Errorf("couldn't find the randomness input")
	}
	//TODO: Check the round value == constant value in the workflow
	suite := pairing.NewSuiteBn256()
	err := bls.Verify(suite, input.Randomness.Public, input.Randomness.Prev,
		input.Randomness.Value)
	if err != nil {
		return nil, xerrors.Errorf("couldn't verify randomness value: %v", err)
	}

	//kvData, ok := inputs[1].I.(KVInputData)
	//if !ok {
	//	return nil, xerrors.Errorf("couldn't find the kv data input")
	//}

	//TODO: verify proof using VerifyFromBlock
	//TODO: get CID from execution request
	//cid := []byte("CID")
	////v, _, _, err := p.SP.Proof.Get(p.CID.Slice())
	//v, _, _, err := input.KVData.StateProof.Proof.Get(cid)
	//if err != nil {
	//	return nil, xerrors.Errorf("couldn't get data from state proof: %v", err)
	//}
	//store := contracts.Storage{}
	//err = protobuf.Decode(v, &store)
	//if err != nil {
	//	return nil, xerrors.Errorf("couldn't decode state contract storage: %v", err)
	//}
	//if store.Store[1].Key != "tickets" {
	//	return nil, xerrors.Errorf("couldn't find the key: tickets")
	//}

	return nil, nil
}

func (r *RandomnessData) Hash() ([]byte, error) {
	h := sha256.New()
	buf, err := r.Public.MarshalBinary()
	if err != nil {
		return nil, err
	}
	h.Write(buf)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(r.Round))
	h.Write(b)
	h.Write(r.Prev)
	h.Write(r.Value)
	return h.Sum(nil), nil
}

package playground

import (
	"crypto/sha256"
	"errors"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

var ContractSigVerID = "sigVer"

type contractSigver struct {
	byzcoin.BasicContract
	SigVerStorage
}

func contractSigverFromBytes(in []byte) (byzcoin.Contract, error) {
	cv := &contractSigver{}
	err := protobuf.Decode(in, &cv.SigVerStorage)
	if err != nil {
		return nil, err
	}
	return cv, nil
}

func (c *contractSigver) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	st := &c.SigVerStorage
	svd := &SigVerData{}
	sBuf := inst.Spawn.Args.Search("request")
	if sBuf == nil {
		log.Errorf("Key:request has no value")
		return
	}
	err = protobuf.Decode(sBuf, svd)
	if err != nil {
		log.Errorf("Protobuf decode failed")
		return
	}
	h := sha256.New()
	h.Write(svd.Data)
	digest := h.Sum(nil)
	err = schnorr.Verify(cothority.Suite, svd.Publics[0], digest, svd.Sig)
	if err != nil {
		log.Errorf("Sig verification failed: %v", err)
		return
	}
	log.Info("Sig verification success")
	st.Storage = append(st.Storage, *svd)
	stBuf, err := protobuf.Encode(&c.SigVerStorage)
	if err != nil {
		return
	}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Create, inst.DeriveID(""), ContractSigVerID, stBuf, darcID),
	}
	return
}

func (c *contractSigver) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}
	if inst.Invoke.Command != "bls" {
		return nil, nil, errors.New("Invoke only works with bls")
	}

	var blssig protocol.BlsSignature
	st := &c.SigVerStorage
	svd := &SigVerData{}
	sBuf := inst.Invoke.Args.Search("request")
	if sBuf == nil {
		log.Errorf("Key:request has no value")
		return
	}
	err = protobuf.Decode(sBuf, svd)
	if err != nil {
		log.Errorf("Protobuf decode failed")
		return
	}

	blssig = svd.Sig
	h := sha256.New()
	h.Write(svd.Data)
	digest := h.Sum(nil)
	err = blssig.Verify(pairing.NewSuiteBn256(), digest, svd.Publics)
	if err != nil {
		log.Errorf("Sig verification failed: %v", err)
		return
	}
	log.Info("Sig verification success")
	st.Storage = append(st.Storage, *svd)
	stBuf, err := protobuf.Encode(&c.SigVerStorage)
	if err != nil {
		log.Errorf("Protobuf encode error: %v", err)
		return
	}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID, ContractSigVerID, stBuf, darcID),
	}
	return
}

func (c *contractSigver) Delete(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	sc = byzcoin.StateChanges{byzcoin.NewStateChange(byzcoin.Remove, inst.InstanceID, ContractSigVerID, nil, darcID)}
	return
}

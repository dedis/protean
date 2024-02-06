package main

import (
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"go.dedis.ch/kyber/v3/util/random"
	"testing"
)

var suite2 = pairing.NewSuiteBn256()
var two = suite2.Scalar().Add(suite2.Scalar().One(), suite2.Scalar().One())
var three = suite2.Scalar().Add(two, suite2.Scalar().One())

func TestBDN_AggregateSignatures(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private1, public1 := bdn.NewKeyPair(suite, random.New())
	private2, public2 := bdn.NewKeyPair(suite, random.New())
	sig1, err := bdn.Sign(suite, private1, msg)
	require.NoError(t, err)
	sig2, err := bdn.Sign(suite, private2, msg)
	require.NoError(t, err)
	t.Log("sizes:", len(sig1), len(sig2))

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)

	_, err = bdn.AggregateSignatures(suite, [][]byte{sig1}, mask)
	require.Error(t, err)

	aggregatedSig, err := bdn.AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := bdn.AggregatePublicKeys(suite, mask)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = bdn.Verify(suite, aggregatedKey, msg, sig)
	require.NoError(t, err)

	mask.SetBit(1, false)
	aggregatedKey, err = bdn.AggregatePublicKeys(suite, mask)

	err = bdn.Verify(suite, aggregatedKey, msg, sig)
	t.Log("agg:", len(sig))
	require.Error(t, err)
}

package core

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/onet/v3"
	"testing"
)

var testSuite = pairing.NewSuiteBn256()

func TestClient_TestSigning(t *testing.T) {
	local := onet.NewTCPTest(testSuite)
	_, roster, _ := local.GenTree(10, false)
	defer local.CloseAll()

	cl := NewClient()
	msg := []byte("serkan is my girl")

	reply, err := cl.TestSigning(roster, msg)
	require.NoError(t, err)
	require.NotNil(t, reply)
	h := testSuite.Hash()
	h.Write(msg)
	require.True(t, bytes.Equal(h.Sum(nil), reply.Hash))
	publics := roster.ServicePublics(ServiceName)
	require.NoError(t, reply.Signature.VerifyWithPolicy(testSuite, msg, publics,
		sign.NewThresholdPolicy(7)))
	require.Error(t, reply.Signature.VerifyWithPolicy(testSuite, msg, publics,
		sign.NewThresholdPolicy(8)))
}

package easyneff

import (
	"crypto/sha256"
	"github.com/dedis/protean/easyneff/protocol"
	"github.com/dedis/protean/threshold"
	"github.com/dedis/protean/threshold/utils"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/onet/v3"
	"testing"

	protean "github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3/log"
)

var uname string
var wname string

var testSuite = pairing.NewSuiteBn256()

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestShuffle_DKG(t *testing.T) {
	total := 20
	nodeCount := total / 2
	thresh := nodeCount - (nodeCount-1)/3
	local := onet.NewTCPTest(cothority.Suite)
	_, roster, _ := local.GenTree(total, true)
	defer local.CloseAll()
	thRoster := onet.NewRoster(roster.List[:nodeCount])
	shRoster := onet.NewRoster(roster.List[nodeCount:])

	// Initialize DKG at the threshold encryption unit
	thCl := threshold.NewClient(thRoster)
	_, err := thCl.InitUnit()
	require.NoError(t, err)
	id := utils.GenerateRandBytes()
	dkgReply, err := thCl.InitDKG(id)
	require.NoError(t, err)

	cleartext := []byte("Go Beavers, beat Wisconsin!")
	// Use the DKG key for encryption
	pairs, kp := generateRequest(10, cleartext, dkgReply.X)

	shCl := NewClient(shRoster)
	_, err = shCl.InitUnit()
	require.NoError(t, err)
	shReply, err := shCl.Shuffle(pairs, kp.Public)
	require.NoError(t, err)
	n := len(shRoster.List)
	require.Equal(t, n, len(shReply.Proofs))
	require.NotNil(t, shReply.Signature)

	// Verify BLS signature
	hash, err := protocol.CalculateHash(shReply.Proofs)
	require.NoError(t, err)
	publics := shRoster.ServicePublics(blscosi.ServiceName)
	require.NoError(t, shReply.Signature.VerifyWithPolicy(testSuite, hash,
		publics, sign.NewThresholdPolicy(thresh)))

	var ctexts []protean.ElGamalPair
	cs := shReply.Proofs[n-1].Pairs
	for _, p := range cs.Pairs {
		ctexts = append(ctexts, p)
	}
	decReply, err := thCl.Decrypt(id, ctexts)
	require.NoError(t, err)
	h := sha256.New()
	for _, p := range decReply.Ps {
		msg, err := p.Data()
		require.NoError(t, err)
		require.Equal(t, cleartext, msg)
		h.Write(msg)
	}
	hash = h.Sum(nil)
	publics = thRoster.ServicePublics(blscosi.ServiceName)
	require.NoError(t, decReply.Signature.VerifyWithPolicy(testSuite, hash,
		publics, sign.NewThresholdPolicy(thresh)))
}

func TestShuffle_EGDecrypt(t *testing.T) {
	total := 7
	threshold := total - (total-1)/3
	local := onet.NewTCPTest(cothority.Suite)
	_, roster, _ := local.GenTree(total, true)
	defer local.CloseAll()

	cl := NewClient(roster)
	_, err := cl.InitUnit()
	require.NoError(t, err)

	// Generate inputs for shuffling
	cleartext := []byte("Go Beavers, beat Wisconsin!")
	pairs, kp := generateRequest(10, cleartext, nil)
	reply, err := cl.Shuffle(pairs, kp.Public)
	require.NoError(t, err)
	//// verification should succeed
	n := len(roster.List)
	require.Equal(t, n, len(reply.Proofs))
	require.NotNil(t, reply.Signature)
	//require.NoError(t, reply.ShuffleVerify(nil, req.H, req.Pairs, unitRoster.Publics()))

	// Verify BLS signature
	hash, err := protocol.CalculateHash(reply.Proofs)
	require.NoError(t, err)
	publics := roster.ServicePublics(blscosi.ServiceName)
	require.NoError(t, reply.Signature.VerifyWithPolicy(testSuite, hash,
		publics, sign.NewThresholdPolicy(threshold)))

	// Should be able to decrypt the shuffled ciphertexts
	cs := reply.Proofs[n-1].Pairs
	for _, p := range cs.Pairs {
		pt := protean.ElGamalDecrypt(kp.Private, p)
		data, err := pt.Data()
		require.NoError(t, err)
		require.Equal(t, cleartext, data)
	}
}

// Generates ShuffleRequest messages that are used for executing the Shuffle
// transaction at the shuffler unit.
//
// Input:
//   - n   - number of ciphertexts to shuffle
//   - msg - plaintext message
//   - pub - public key to be used for encryption. If nil, a new key pair is
//   generated for encryption
//   - ed  - execution plan data (Protean-related)
//
// Output:
//   - req - ShuffleRequest with ciphertexts
//   - kp  - If a public key is provided, key pair only contains that public
//   key. Otherwise (pub = nil), key pair is the newly-generated key pair
func generateRequest(n int, msg []byte, pub kyber.Point) (protean.ElGamalPairs, *key.Pair) {
	var kp *key.Pair
	if pub != nil {
		kp = &key.Pair{
			Public: pub,
		}
	} else {
		kp = key.NewKeyPair(cothority.Suite)
	}
	pairs := make([]protean.ElGamalPair, n)
	for i := range pairs {
		c := protean.ElGamalEncrypt(kp.Public, msg)
		pairs[i] = protean.ElGamalPair{K: c.K, C: c.C}
	}
	return protean.ElGamalPairs{Pairs: pairs}, kp
}

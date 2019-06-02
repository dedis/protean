package easyneff

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/util/random"
)

func TestElGamal(t *testing.T) {
	secret := cothority.Suite.Scalar().Pick(random.New())
	public := cothority.Suite.Point().Mul(secret, nil)
	message := []byte("she sells sea shells")

	K, C := Encrypt(public, message)
	dec, _ := Decrypt(secret, K, C).Data()
	assert.Equal(t, message, dec)
}

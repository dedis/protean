package threshold

import (
	"encoding/hex"

	"go.dedis.ch/kyber/v3/util/random"
)

func hexToBytes(str string) ([]byte, error) {
	return hex.DecodeString(str)
}

func GenerateRandBytes() []byte {
	slc := make([]byte, 32)
	random.Bytes(slc, random.New())
	return slc
}

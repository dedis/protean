package utils

import (
	"encoding/hex"
	"fmt"
	protean "github.com/dedis/protean/utils"
	"go.dedis.ch/kyber/v3"

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

func GenerateMesgs(count int, m string, key kyber.Point) ([][]byte, []protean.ElGamalPair) {
	mesgs := make([][]byte, count)
	cs := make([]protean.ElGamalPair, count)
	for i := 0; i < count; i++ {
		s := fmt.Sprintf("%s%s%d%s", m, " -- ", i, "!")
		mesgs[i] = []byte(s)
		c := protean.ElGamalEncrypt(key, mesgs[i])
		cs[i] = c
	}
	return mesgs, cs
}

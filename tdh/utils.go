package tdh

import (
	"crypto/sha256"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/kyber/v3/xof/keccak"
)

//func (c *Client) Encrypt(suite suites.Suite, genData []byte, X kyber.Point, mesg []byte) *Ciphertext {
func Encrypt(suite suites.Suite, genData []byte, X kyber.Point, mesg []byte) *Ciphertext {
	ctext := &Ciphertext{}
	r := suite.Scalar().Pick(suite.RandomStream())
	C := suite.Point().Mul(r, X)
	ctext.U = suite.Point().Mul(r, nil)

	// Create proof
	if len(mesg) > suite.Point().EmbedLen() {
		return nil
	}
	kp := suite.Point().Embed(mesg, suite.RandomStream())
	ctext.C = suite.Point().Add(C, kp)

	gBar := suite.Point().Embed(genData, keccak.New(genData))
	ctext.Ubar = suite.Point().Mul(r, gBar)
	s := suite.Scalar().Pick(suite.RandomStream())
	w := suite.Point().Mul(s, nil)
	wBar := suite.Point().Mul(s, gBar)
	hash := sha256.New()
	ctext.C.MarshalTo(hash)
	ctext.U.MarshalTo(hash)
	ctext.Ubar.MarshalTo(hash)
	w.MarshalTo(hash)
	wBar.MarshalTo(hash)
	ctext.E = suite.Scalar().SetBytes(hash.Sum(nil))
	ctext.F = suite.Scalar().Add(s, suite.Scalar().Mul(ctext.E, r))
	return ctext
}

//func (c *Client) RecoverPlaintext(reply *DecryptReply, xc kyber.Scalar) ([]byte, error) {
func RecoverPlaintext(reply *DecryptReply, xc kyber.Scalar) ([]byte, error) {
	var data []byte
	var err error
	if xc == nil {
		xHatInv := cothority.Suite.Point().Neg(reply.XhatEnc)
		dataPt := cothority.Suite.Point().Add(reply.C, xHatInv)
		data, err = dataPt.Data()
	} else {
		xcInv := xc.Clone().Neg(xc)
		xHatDec := reply.X.Clone().Mul(xcInv, reply.X)
		xHat := xHatDec.Clone().Add(reply.XhatEnc, xHatDec)
		xHatInv := xHat.Clone().Neg(xHat)
		xHatInv.Add(reply.C, xHatInv)
		data, err = xHatInv.Data()
	}
	return data, err
}

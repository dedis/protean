package easyneff

//// Encrypt performs the ElGamal encryption algorithm.
//func Encrypt(public kyber.Point, message []byte) (K, C kyber.Point) {
//if len(message) > cothority.Suite.Point().EmbedLen() {
//panic("message size is too long")
//}
//M := cothority.Suite.Point().Embed(message, random.New())

//// ElGamal-encrypt the point to produce ciphertext (K,C).
//k := cothority.Suite.Scalar().Pick(random.New()) // ephemeral private key
//K = cothority.Suite.Point().Mul(k, nil)          // ephemeral DH public key
//S := cothority.Suite.Point().Mul(k, public)      // ephemeral DH shared secret
//C = S.Add(S, M)                                  // message blinded with secret
//return
//}

//// Decrypt performs the ElGamal decryption algorithm.
//func Decrypt(private kyber.Scalar, K, C kyber.Point) kyber.Point {
//// ElGamal-decrypt the ciphertext (K,C) to reproduce the message.
//S := cothority.Suite.Point().Mul(private, K) // regenerate shared secret
//return cothority.Suite.Point().Sub(C, S)     // use to un-blind the message
//}

//// Verify performs verifies the proof of a Neff shuffle.
//func Verify(prf []byte, G, H kyber.Point, x, y, xbar, ybar []kyber.Point) error {
//if len(x) < 2 || len(y) < 2 || len(xbar) < 2 || len(ybar) < 2 {
//return errors.New("cannot verify less than 2 points")
//}
//verifier := shuffle.Verifier(cothority.Suite, G, H, x, y, xbar, ybar)
//return proof.HashVerify(cothority.Suite, "", verifier, prf)
//}

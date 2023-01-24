package protocol

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bls"
	"golang.org/x/xerrors"
	"sync"
	"time"

	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	dkgprotocol "go.dedis.ch/cothority/v3/dkg/pedersen"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	_, err := onet.GlobalProtocolRegister(ThreshProtoName, NewThreshDecrypt)
	if err != nil {
		log.Errorf("Cannot register protocol: %v", err)
		panic(err)
	}
	network.RegisterMessages(&DecryptShare{}, &DecryptShareReply{},
		&Reconstruct{}, &ReconstructReply{})
}

type ThreshDecrypt struct {
	*onet.TreeNodeInstance
	Shared *dkgprotocol.SharedSecret
	Poly   *share.PubPoly
	Cs     []utils.ElGamalPair

	partials []Partial // len(partials) == number of ciphertexts to be dec
	Ptexts   []kyber.Point

	Threshold int
	Failures  int

	FinalSignature protocol.BlsSignature
	Decrypted      chan bool
	// private fields
	suite              *pairing.SuiteBn256
	pubShares          map[int]kyber.Point
	dsReplies          []DecryptShareReply
	reconstructReplies []ReconstructReply
	BlsPublic          kyber.Point
	BlsPublics         []kyber.Point
	BlsSk              kyber.Scalar
	mask               *sign.Mask
	timeout            *time.Timer
	doneOnce           sync.Once
}

func NewThreshDecrypt(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	d := &ThreshDecrypt{
		TreeNodeInstance: n,
		Decrypted:        make(chan bool, 1),
		suite:            pairing.NewSuiteBn256(),
	}
	err := d.RegisterHandlers(d.decryptShare, d.decryptShareReply,
		d.reconstruct, d.reconstructReply)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (d *ThreshDecrypt) Start() error {
	log.Lvl3("Starting Protocol")
	if d.Shared == nil {
		d.finish(false)
		return errors.New("initialize Shared first")
	}
	if len(d.Cs) == 0 {
		d.finish(false)
		return errors.New("empty ciphertext list")
	}
	ds := &DecryptShare{
		Cs: d.Cs,
	}
	d.partials = make([]Partial, len(d.Cs))
	d.pubShares = make(map[int]kyber.Point)
	d.timeout = time.AfterFunc(1*time.Minute, func() {
		log.Lvl1("ThreshDecrypt protocol timeout")
		d.finish(false)
	})
	errs := d.Broadcast(ds)
	if len(errs) > (len(d.Roster().List) - d.Threshold) {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return errors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (d *ThreshDecrypt) decryptShare(r structDecryptShare) error {
	log.Lvl3(d.Name() + ": starting decryptShare")
	d.Cs = r.Cs
	shares := make([]Share, len(d.Cs))
	for i, c := range d.Cs {
		sh := cothority.Suite.Point().Mul(d.Shared.V, c.K)
		ei, fi := d.generateDecProof(c.K, sh)
		shares[i].Sh = &share.PubShare{I: d.Shared.Index, V: sh}
		shares[i].Ei = ei
		shares[i].Fi = fi
	}
	return d.SendToParent(&DecryptShareReply{Shares: shares})
}

// decryptShareReply is the root-node waiting for replies
func (d *ThreshDecrypt) decryptShareReply(r structDecryptShareReply) error {
	if r.Shares == nil {
		log.Lvl2("Node", r.ServerIdentity, "refused to reply")
		d.Failures++
		if d.Failures > (len(d.Roster().List) - d.Threshold) {
			log.Lvl2(r.ServerIdentity, "couldn't get enough shares")
			d.finish(false)
		}
		return nil
	} else {
		// Verify decryption proof
		idx := r.Shares[0].Sh.I
		d.pubShares[idx] = d.Poly.Eval(idx).V
		for i, c := range d.Cs {
			tmpSh := r.Shares[i]
			ok := verifyDecProof(tmpSh.Sh.V, tmpSh.Ei, tmpSh.Fi, c.K,
				d.pubShares[tmpSh.Sh.I])
			if !ok {
				log.Lvl2("received invalid share for ciphertext %d from"+
					" node %d", i, tmpSh.Sh.I)
				d.Failures++
				if d.Failures > len(d.Roster().List)-d.Threshold {
					log.Lvl2(r.ServerIdentity, "couldn't get enough shares")
					d.finish(false)
				}
				return nil
			}
		}
	}

	d.dsReplies = append(d.dsReplies, r.DecryptShareReply)

	if len(d.dsReplies) == d.Threshold-1 {
		d.Failures = 0
		idx := -1
		for i, c := range d.Cs {
			// Root prepares its shares
			sh := cothority.Suite.Point().Mul(d.Shared.V, c.K)
			ei, fi := d.generateDecProof(c.K, sh)
			ps := &share.PubShare{I: d.Shared.Index, V: sh}
			d.partials[i].Shares = append(d.partials[i].Shares, ps)
			d.partials[i].Eis = append(d.partials[i].Eis, ei)
			d.partials[i].Fis = append(d.partials[i].Fis, fi)
			for _, rep := range d.dsReplies {
				tmpSh := rep.Shares[i]
				d.partials[i].Shares = append(d.partials[i].Shares, tmpSh.Sh)
				d.partials[i].Eis = append(d.partials[i].Eis, tmpSh.Ei)
				d.partials[i].Fis = append(d.partials[i].Fis, tmpSh.Fi)
			}
			idx = ps.I
		}
		d.pubShares[idx] = d.Poly.Eval(idx).V
		d.Ptexts = make([]kyber.Point, len(d.partials))
		for i, partial := range d.partials {
			d.Ptexts[i] = d.recoverCommit(d.Cs[i], partial.Shares)
		}
		// prepare BLS signature and mask
		hash, err := d.calculateHash()
		if err != nil {
			log.Errorf("root couldn't calculate the hash: %v", err)
			d.finish(false)
			return err
		}
		rr, err := d.generateReconstructReply(hash)
		if err != nil {
			log.Errorf("root couldn't generate reconstruct reply: %v", err)
			d.finish(false)
			return err
		}
		//d.mask, err = sign.NewMask(d.suite, d.Publics(), d.Public())
		d.mask, err = sign.NewMask(d.suite, d.BlsPublics, d.BlsPublic)
		if err != nil {
			log.Errorf("root couldn't generate mask: %v", err)
			d.finish(false)
			return err
		}
		// add root's reconstruct reply to the array
		d.reconstructReplies = append(d.reconstructReplies, *rr)
		errs := d.Broadcast(&Reconstruct{
			Partials: d.partials,
			Publics:  d.pubShares,
			Hash:     hash,
		})
		if len(errs) > (len(d.Roster().List) - d.Threshold) {
			log.Errorf("Some nodes failed with error(s) %v", errs)
			d.finish(false)
		}
	}
	return nil
}

func (d *ThreshDecrypt) reconstruct(r structReconstruct) error {
	log.Lvl3(d.Name() + ": starting reconstruct")
	defer d.Done()
	d.Ptexts = make([]kyber.Point, len(r.Partials))
	for i, c := range d.Cs {
		partial := r.Partials[i]
		for j, _ := range partial.Shares {
			ok := verifyDecProof(partial.Shares[j].V, partial.Eis[j],
				partial.Fis[j], c.K, r.Publics[partial.Shares[j].I])
			if !ok {
				log.Errorf("%s cannot verify decryption proof", d.Name())
				return cothority.ErrorOrNil(d.SendToParent(&ReconstructReply{}),
					"sending ReconstructReply to parent")
			}
		}
		d.Ptexts[i] = d.recoverCommit(c, partial.Shares)
	}
	hash, err := d.calculateHash()
	if err != nil {
		log.Errorf("root couldn't calculate the hash: %v", err)
		return cothority.ErrorOrNil(d.SendToParent(&ReconstructReply{}),
			"sending ReconstructReply to parent")
	}
	if !bytes.Equal(r.Hash, hash) {
		log.Errorf("hashes do not match")
		return cothority.ErrorOrNil(d.SendToParent(&ReconstructReply{}),
			"sending ReconstructReply to parent")
	}
	rr, err := d.generateReconstructReply(hash)
	if err != nil {
		log.Errorf("%s couldn't generate reconstruct reply: %v", d.Name(), err)
	}
	return cothority.ErrorOrNil(d.SendToParent(rr),
		"sending ReconstructReply to parent")
}

func (d *ThreshDecrypt) reconstructReply(r structReconstructReply) error {
	if r.Signature == nil {
		log.Lvl2("Node", r.ServerIdentity, "refused to send back reconstruct reply")
		d.Failures++
		if d.Failures > (len(d.Roster().List) - d.Threshold) {
			log.Lvl2(r.ServerIdentity, "couldn't get enough reconstruct replies")
			d.finish(false)
		}
		return nil
	}
	_, index := searchPublicKey(d.TreeNodeInstance, r.ServerIdentity)
	d.mask.SetBit(index, true)
	d.reconstructReplies = append(d.reconstructReplies, r.ReconstructReply)
	if len(d.reconstructReplies) == d.Threshold {
		finalSignature := d.suite.G1().Point()
		for _, reply := range d.reconstructReplies {
			sig, err := reply.Signature.Point(d.suite)
			if err != nil {
				d.finish(false)
				return err
			}
			finalSignature = finalSignature.Add(finalSignature, sig)
		}
		sig, err := finalSignature.MarshalBinary()
		if err != nil {
			d.finish(false)
			return err
		}
		d.FinalSignature = append(sig, d.mask.Mask()...)
		d.finish(true)
	}
	return nil
}

func (d *ThreshDecrypt) generateReconstructReply(data []byte) (*ReconstructReply, error) {
	sig, err := bls.Sign(d.suite, d.BlsSk, data)
	if err != nil {
		return &ReconstructReply{}, err
	}
	return &ReconstructReply{Signature: sig}, nil
}

func (d *ThreshDecrypt) generateDecProof(u kyber.Point, sh kyber.Point) (kyber.Scalar, kyber.Scalar) {
	si := cothority.Suite.Scalar().Pick(d.Suite().RandomStream())
	uiHat := cothority.Suite.Point().Mul(si, u)
	hiHat := cothority.Suite.Point().Mul(si, nil)
	hash := sha256.New()
	sh.MarshalTo(hash)
	uiHat.MarshalTo(hash)
	hiHat.MarshalTo(hash)
	ei := cothority.Suite.Scalar().SetBytes(hash.Sum(nil))
	fi := cothority.Suite.Scalar().Add(si, cothority.Suite.Scalar().Mul(ei, d.Shared.V))
	return ei, fi
}

func verifyDecProof(sh kyber.Point, ei kyber.Scalar, fi kyber.Scalar,
	u kyber.Point, pub kyber.Point) bool {
	// sh = ui // u = g^r // pub = h^i
	//Verify proofs
	ufi := cothority.Suite.Point().Mul(fi, u)
	uiei := cothority.Suite.Point().Mul(cothority.Suite.Scalar().Neg(ei), sh)
	uiHat := cothority.Suite.Point().Add(ufi, uiei)
	gfi := cothority.Suite.Point().Mul(fi, nil)
	hiei := cothority.Suite.Point().Mul(cothority.Suite.Scalar().Neg(ei), pub)
	hiHat := cothority.Suite.Point().Add(gfi, hiei)
	hash := sha256.New()
	sh.MarshalTo(hash)
	uiHat.MarshalTo(hash)
	hiHat.MarshalTo(hash)
	e := cothority.Suite.Scalar().SetBytes(hash.Sum(nil))
	return e.Equal(ei)
}

func (d *ThreshDecrypt) recoverCommit(cs utils.ElGamalPair, pubShares []*share.PubShare) kyber.Point {
	rc, err := share.RecoverCommit(cothority.Suite, pubShares, d.Threshold, len(d.List()))
	if err != nil {
		log.Errorf("cannot recover message: %v", err)
		return nil
	}
	p := cothority.Suite.Point().Sub(cs.C, rc)
	return p
}

func (d *ThreshDecrypt) calculateHash() ([]byte, error) {
	h := sha256.New()
	for i, ptext := range d.Ptexts {
		data, err := ptext.Data()
		if err != nil {
			return nil, xerrors.Errorf("couldn't extract data item %d: %v", i, err)
		}
		h.Write(data)
	}
	return h.Sum(nil), nil
}

func searchPublicKey(p *onet.TreeNodeInstance, servID *network.ServerIdentity) (
	kyber.Point, int) {
	for idx, si := range p.Roster().List {
		if si.Equal(servID) {
			return p.NodePublic(si), idx
		}
	}
	return nil, -1
}

func (d *ThreshDecrypt) finish(result bool) {
	d.timeout.Stop()
	select {
	case d.Decrypted <- result:
		// succeeded
	default:
		// would have blocked because some other call to finish()
		// beat us.
	}
	d.doneOnce.Do(func() { d.Done() })
}

package threshold

import (
	"crypto/sha256"
	"errors"
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
	network.RegisterMessages(&PartialRequest{}, &PartialReply{})
}

type ThreshDecrypt struct {
	*onet.TreeNodeInstance
	Shared    *dkgprotocol.SharedSecret
	Poly      *share.PubPoly
	Cs        []*utils.ElGamalPair
	Partials  []*Partial // len(Partials) == number of ciphertexts to be dec
	Server    bool       // If false - do not reconstruct secret here
	Threshold int
	Failures  int
	Decrypted chan bool
	// private fields
	replies  []PartialReply
	timeout  *time.Timer
	doneOnce sync.Once
}

func NewThreshDecrypt(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	d := &ThreshDecrypt{
		TreeNodeInstance: n,
		Decrypted:        make(chan bool, 1),
		Threshold:        len(n.Roster().List) - (len(n.Roster().List)-1)/3,
	}
	err := d.RegisterHandlers(d.decrypt, d.decryptReply)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (d *ThreshDecrypt) Start() error {
	log.Lvl3("Starting Protocol")
	if d.Shared == nil {
		d.finish(false)
		return errors.New("Initialize Shared first")
	}
	if len(d.Cs) == 0 {
		d.finish(false)
		return errors.New("Empty ciphertext list")
	}
	pd := &PartialRequest{
		Cs: d.Cs,
	}
	d.timeout = time.AfterFunc(1*time.Minute, func() {
		log.Lvl1("ThreshDecrypt protocol timeout")
		d.finish(false)
	})
	errs := d.Broadcast(pd)
	if len(errs) > (len(d.Roster().List)-1)/3 {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return errors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (d *ThreshDecrypt) decrypt(r structPartialRequest) error {
	log.Lvl3(d.Name() + ": starting decrypt")
	defer d.Done()
	shares := make([]*Share, len(r.Cs))
	for i, c := range r.Cs {
		sh := cothority.Suite.Point().Mul(d.Shared.V, c.K)
		ei, fi := d.generateDecProof(c.K, sh)
		shares[i] = &Share{
			Sh: &share.PubShare{I: d.Shared.Index, V: sh},
			Ei: ei,
			Fi: fi,
		}
	}
	return d.SendToParent(&PartialReply{
		Shares: shares,
	})
}

// decryptReply is the root-node waiting for all replies
func (d *ThreshDecrypt) decryptReply(pdr structPartialReply) error {
	if pdr.PartialReply.Shares == nil {
		log.Lvl2("Node", pdr.ServerIdentity, "refused to reply")
		d.Failures++
		if d.Failures > len(d.Roster().List)-d.Threshold {
			log.Lvl2(pdr.ServerIdentity, "couldn't get enough shares")
			d.finish(false)
		}
		return nil
	}
	d.replies = append(d.replies, pdr.PartialReply)

	// minus one to exclude the root
	if len(d.replies) >= int(d.Threshold-1) {
		// Each Partial contains n shares/eis/fis - one from each node
		for i := 0; i < len(d.Cs); i++ {
			d.Partials = append(d.Partials, &Partial{})
		}
		// Root node prepares its share by performing EG decryption
		for i, c := range d.Cs {
			sh := cothority.Suite.Point().Mul(d.Shared.V, c.K)
			if d.Server == false {
				// Root node also generates decryption proofs
				// since reconstruction is going to happen on
				// the client-side
				ei, fi := d.generateDecProof(c.K, sh)
				d.Partials[i].Eis = append(d.Partials[i].Eis, ei)
				d.Partials[i].Fis = append(d.Partials[i].Fis, fi)
				d.Partials[i].Pubs = append(d.Partials[i].Pubs, d.Poly.Eval(d.Shared.Index).V)
			}
			d.Partials[i].Shares = append(d.Partials[i].Shares, &share.PubShare{I: d.Shared.Index, V: sh})
		}

		// pubs is used to save doing poly.eval for each ciphertext
		pubs := make([]kyber.Point, len(d.List()))
		for _, r := range d.replies {
			idx := r.Shares[0].Sh.I
			pubs[idx] = d.Poly.Eval(idx).V
		}
		for i, c := range d.Cs {
			for _, r := range d.replies {
				tmpSh := r.Shares[i]
				if d.Server {
					// if server flag set, then verify
					// decryption proof
					ok := VerifyDecProof(tmpSh.Sh.V, tmpSh.Ei, tmpSh.Fi, c.K, pubs[tmpSh.Sh.I])
					if ok {
						d.Partials[i].Shares = append(d.Partials[i].Shares, tmpSh.Sh)
					} else {
						log.LLvlf1("Received invalid share for ciphertext %d from node %d", i, tmpSh.Sh.I)
					}
				} else {
					d.Partials[i].Shares = append(d.Partials[i].Shares, tmpSh.Sh)
					d.Partials[i].Eis = append(d.Partials[i].Eis, tmpSh.Ei)
					d.Partials[i].Fis = append(d.Partials[i].Fis, tmpSh.Fi)
					d.Partials[i].Pubs = append(d.Partials[i].Pubs, pubs[tmpSh.Sh.I])
				}
			}
		}
		d.finish(true)
	}
	// If we are leaving by here it means that we do not have
	// enough replies yet. We must eventually trigger a finish()
	// somehow. It will either happen because we get another
	// reply, and now we have enough, or because we get enough
	// failures and know to give up, or because d.timeout triggers
	// and calls finish(false) in it's callback function.
	return nil
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

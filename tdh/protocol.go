package tdh

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"go.dedis.ch/cothority/v3"
	dkgprotocol "go.dedis.ch/cothority/v3/dkg/pedersen"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	_, err := onet.GlobalProtocolRegister(TDHProtoName, NewTDHDecrypt)
	if err != nil {
		log.Errorf("Cannot register protocol: %v", err)
		panic(err)
	}
	network.RegisterMessages(&PartialRequest{}, &PartialReply{})
}

type TDHDecrypt struct {
	*onet.TreeNodeInstance
	Shared    *dkgprotocol.SharedSecret
	Poly      *share.PubPoly
	U         kyber.Point
	Xc        kyber.Point
	Threshold int
	Failures  int
	Decrypted chan bool
	Uis       []*share.PubShare
	// private fields
	replies  []PartialReply
	timeout  *time.Timer
	doneOnce sync.Once
}

func NewTDHDecrypt(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	d := &TDHDecrypt{
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

func (d *TDHDecrypt) Start() error {
	log.Lvl3("Starting Protocol")
	if d.Shared == nil {
		d.finish(false)
		return errors.New("Initialize Shared first")
	}
	if d.U == nil {
		d.finish(false)
		return errors.New("Initialize U first")
	}
	pd := &PartialRequest{
		U:  d.U,
		Xc: d.Xc,
	}
	d.timeout = time.AfterFunc(1*time.Minute, func() {
		log.Lvl1("TDHDecrypt protocol timeout")
		d.finish(false)
	})
	errs := d.Broadcast(pd)
	if len(errs) > (len(d.Roster().List)-1)/3 {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return errors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (d *TDHDecrypt) decrypt(r structPartialRequest) error {
	log.Lvl3(d.Name() + ": starting decrypt")
	defer d.Done()

	ui, err := d.getUI(r.U, r.Xc)
	if err != nil {
		return nil
	}

	// Calculating proofs
	var uiHat kyber.Point
	si := cothority.Suite.Scalar().Pick(d.Suite().RandomStream())
	if r.Xc == nil {
		uiHat = cothority.Suite.Point().Mul(si, r.U)
	} else {
		uiHat = cothority.Suite.Point().Mul(si, cothority.Suite.Point().Add(r.U, r.Xc))
	}
	hiHat := cothority.Suite.Point().Mul(si, nil)
	hash := sha256.New()
	ui.V.MarshalTo(hash)
	uiHat.MarshalTo(hash)
	hiHat.MarshalTo(hash)
	ei := cothority.Suite.Scalar().SetBytes(hash.Sum(nil))

	return d.SendToParent(&PartialReply{
		Ui: ui,
		Ei: ei,
		Fi: cothority.Suite.Scalar().Add(si, cothority.Suite.Scalar().Mul(ei, d.Shared.V)),
	})
}

// decryptReply is the root-node waiting for all replies and generating
// the decrypted message
func (d *TDHDecrypt) decryptReply(pdr structPartialReply) error {
	if pdr.PartialReply.Ui == nil {
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
		d.Uis = make([]*share.PubShare, len(d.List()))
		var err error
		d.Uis[0], err = d.getUI(d.U, d.Xc)
		if err != nil {
			return err
		}
		for _, r := range d.replies {
			// Verify proofs
			var ufi kyber.Point
			if d.Xc == nil {
				ufi = cothority.Suite.Point().Mul(r.Fi, d.U)
			} else {
				ufi = cothority.Suite.Point().Mul(r.Fi, cothority.Suite.Point().Add(d.U, d.Xc))
			}
			uiei := cothority.Suite.Point().Mul(cothority.Suite.Scalar().Neg(r.Ei), r.Ui.V)
			uiHat := cothority.Suite.Point().Add(ufi, uiei)
			gfi := cothority.Suite.Point().Mul(r.Fi, nil)
			gxi := d.Poly.Eval(r.Ui.I).V
			hiei := cothority.Suite.Point().Mul(cothority.Suite.Scalar().Neg(r.Ei), gxi)
			hiHat := cothority.Suite.Point().Add(gfi, hiei)
			hash := sha256.New()
			r.Ui.V.MarshalTo(hash)
			uiHat.MarshalTo(hash)
			hiHat.MarshalTo(hash)
			e := cothority.Suite.Scalar().SetBytes(hash.Sum(nil))
			if e.Equal(r.Ei) {
				d.Uis[r.Ui.I] = r.Ui
			} else {
				log.Lvl1("Received invalid share from node", r.Ui.I)
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

func (d *TDHDecrypt) getUI(U, Xc kyber.Point) (*share.PubShare, error) {
	v := cothority.Suite.Point().Mul(d.Shared.V, U)
	if Xc != nil {
		v.Add(v, cothority.Suite.Point().Mul(d.Shared.V, Xc))
	}
	return &share.PubShare{I: d.Shared.Index, V: v}, nil
}

func (d *TDHDecrypt) finish(result bool) {
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

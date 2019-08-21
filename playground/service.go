package playground

import (
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

// This service is only used because we need to register our contracts to
// the ByzCoin service. So we create this stub and add contracts to it
// from the `contracts` directory.

func init() {
	_, err := onet.RegisterNewService("playground", newService)
	log.ErrFatal(err)
}

// Service is only used to being able to store our contracts
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	err := byzcoin.RegisterContract(c, ContractSigVerID, contractSigverFromBytes)
	if err != nil {
		log.Errorf("Cannot register contract: %v", err)
	}
	err = byzcoin.RegisterContract(c, ContractElGamalID, contractElGamalFromBytes)
	if err != nil {
		log.Errorf("Cannot register contract: %v", err)
	}
	return s, nil
}

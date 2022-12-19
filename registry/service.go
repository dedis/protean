package registry

import (
	"github.com/dedis/protean/contracts"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/onet/v3"
)

var registryID onet.ServiceID

const ServiceName = "RegistryService"

func init() {
	var err error
	registryID, err = onet.RegisterNewService(ServiceName, newService)
	if err != nil {
		panic(err)
	}
	err = byzcoin.RegisterGlobalContract(contracts.ContractKeyValueID, contracts.ContractKeyValueFromBytes)
}

type Service struct {
	*onet.ServiceProcessor
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	return s, nil
}

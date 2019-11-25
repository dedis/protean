module github.com/dedis/protean

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/stretchr/testify v1.4.0
	go.dedis.ch/cothority/v3 v3.3.2
	go.dedis.ch/cothority/v4 v4.0.0-20191122071555-9134c9866b8c // indirect
	go.dedis.ch/kyber/v3 v3.0.6
	go.dedis.ch/onet/v3 v3.0.27
	go.dedis.ch/protobuf v1.0.9
	gopkg.in/urfave/cli.v1 v1.20.0
)

//replace go.dedis.ch/onet/v3 => ../onet
//replace go.dedis.ch/cothority/v3/calypso => ../../../cothority/calypso
replace go.dedis.ch/cothority/v3 => ../../../cothority

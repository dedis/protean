module github.com/dedis/protean

go 1.14

require (
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/stretchr/testify v1.5.1
	go.dedis.ch/cothority/v3 v3.3.2
	go.dedis.ch/kyber/v3 v3.0.13
	go.dedis.ch/onet/v3 v3.2.10
	go.dedis.ch/protobuf v1.0.11
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	gopkg.in/urfave/cli.v1 v1.20.0
)

replace go.dedis.ch/cothority/v3 => ../../cothority

replace go.dedis.ch/onet/v3 => ../../onet

module github.com/dedis/protean

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/stretchr/testify v1.3.0
	go.dedis.ch/cothority/v3 v3.1.3
	go.dedis.ch/kyber/v3 v3.0.3
	go.dedis.ch/onet/v3 v3.0.20
	go.dedis.ch/protobuf v1.0.6
	gopkg.in/urfave/cli.v1 v1.20.0
)

//replace go.dedis.ch/onet/v3 => ../onet

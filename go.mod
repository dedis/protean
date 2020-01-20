module github.com/dedis/protean

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/stretchr/testify v1.4.0
	go.dedis.ch/cothority/v3 v3.3.2
	go.dedis.ch/kyber/v3 v3.0.11
	go.dedis.ch/onet/v3 v3.0.29
	go.dedis.ch/protobuf v1.0.11
	google.golang.org/appengine v1.4.0
	gopkg.in/urfave/cli.v1 v1.20.0
)

replace go.dedis.ch/cothority/v3 => ../../cothority

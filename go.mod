module github.com/dedis/protean

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/stretchr/testify v1.4.0
	go.dedis.ch/cothority/v3 v3.3.2
	go.dedis.ch/kyber/v3 v3.0.12
	go.dedis.ch/onet/v3 v3.1.0
	go.dedis.ch/protobuf v1.0.11
	golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898
	google.golang.org/appengine v1.4.0
	gopkg.in/urfave/cli.v1 v1.20.0
)

replace go.dedis.ch/cothority/v3 => ../../cothority

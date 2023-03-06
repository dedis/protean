package main

import "go.dedis.ch/onet/v3/simul"
import _ "github.com/dedis/protean/experiments/microbenchmarks/verify/service"
import _ "github.com/dedis/protean/experiments/microbenchmarks/sign/service"

func main() {
	simul.Start()
}

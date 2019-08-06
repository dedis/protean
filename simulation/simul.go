package main

import (
	// Service needs to be imported here to be instantiated.
	_ "github.com/ceyhunalp/protean_code/service"
	"go.dedis.ch/onet/v3/simul"
)

func main() {
	simul.Start()
}

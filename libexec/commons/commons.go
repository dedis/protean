package commons

//TODO: add execution request to input parameters
type ExecutionFn func([]Input) ([]Output, error)

type Input struct {
	I interface{}
}

type Output struct {
	O interface{}
}

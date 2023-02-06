package apps

import (
	"github.com/dedis/protean/libexec/apps/shufdkg"
	"github.com/dedis/protean/libexec/base"
)

func GetFunction(fnName string) base.ExecutionFn {
	switch fnName {
	case "prep_shuf":
		return shufdkg.PrepareShuffle
	case "prep_dec":
		return shufdkg.PrepareDecrypt
	default:
		return nil
	}
}

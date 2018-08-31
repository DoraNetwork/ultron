package constant

import (
	"math/big"
)

var (
	// FIXME: Any method to obtain server's chain id?
	ChainId = big.NewInt(188)
	HomePath = "$HOME/.ultron"
)

package utils

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"reflect"

	"github.com/ethereum/go-ethereum/core"
)

// defaultGenesisBlob is the JSON representation of the default
// genesis file in $GOPATH/src/github.com/tendermint/ethermint/setup/genesis.json
// nolint=lll
var defaultGenesisBlob = []byte(`
{
    "config": {
        "chainId": 15,
        "homesteadBlock": 0,
        "eip155Block": 0,
        "eip158Block": 0
    },
    "nonce": "0xdeadbeefdeadbeef",
    "timestamp": "0x00",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "mixhash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "difficulty": "0x40",
    "gasLimit": "0xF00000000",
	"alloc": {
		"0xedac2dfcfe06f30920219221eccc79a300a8d7e1": { "balance": "10000000000000000000000000000000000" },
		"0x4806202cd62b03be5f6681827d5329409c1e0cdd": { "balance": "10000000000000000000000000000000000" },
		"0x70ade99ba1966cab6584e90220b94154d4b58eb1": { "balance": "10000000000000000000000000000000000" },
		"0xc2816eaf7e9804dc0804b6b33ab3e45b7d1f9823": { "balance": "10000000000000000000000000000000000" }
	}
}`)

var blankGenesis = new(core.Genesis)

var errBlankGenesis = errors.New("could not parse a valid/non-blank Genesis")

// ParseGenesisOrDefault tries to read the content from provided
// genesisPath. If the path is empty or doesn't exist, it will
// use defaultGenesisBytes as the fallback genesis source. Otherwise,
// it will open that path and if it encounters an error that doesn't
// satisfy os.IsNotExist, it returns that error.
func ParseGenesisOrDefault(genesisPath string) (*core.Genesis, error) {
	var genesisBlob = defaultGenesisBlob[:]
	if len(genesisPath) > 0 {
		blob, err := ioutil.ReadFile(genesisPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if len(blob) >= 2 { // Expecting atleast "{}"
			genesisBlob = blob
		}
	}

	genesis := new(core.Genesis)
	if err := json.Unmarshal(genesisBlob, genesis); err != nil {
		return nil, err
	}

	if reflect.DeepEqual(blankGenesis, genesis) {
		return nil, errBlankGenesis
	}

	return genesis, nil
}

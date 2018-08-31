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
		"0x0413c6cc6d4381489815b35118f6fa3a1d45a3f9": { "balance": "10000000000000000000000000000000000" },
		"0x1780858a3eb6f491adb0b30cc5218746b5f9442c": { "balance": "10000000000000000000000000000000000" },
		"0xfa5787ff486c4093a2f6b6708d28e8e8da6d7957": { "balance": "10000000000000000000000000000000000" },
		"0xc6fc3cfcfd5b8c6ffa8d0b77f8611f001b79717b": { "balance": "10000000000000000000000000000000000" },
		"0xcd89dde88bc4e308e436f9f696454840ff795d84": { "balance": "10000000000000000000000000000000000" }
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

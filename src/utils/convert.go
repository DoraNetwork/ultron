package utils

import (
	"encoding/hex"
	"fmt"
	"github.com/tendermint/go-crypto"
	"math/big"
	"strconv"
)

func RemoveFromSlice(slice []interface{}, i int) []interface{} {
	copy(slice[i:], slice[i+1:])
	return slice[:len(slice)-1]
}

func GetPubKey(pubKeyStr string) (pk crypto.PubKey, err error) {
	if len(pubKeyStr) == 0 {
		err = fmt.Errorf("must use --pubkey flag")
		return
	}
	if len(pubKeyStr) == 66 { //64 for ED25519
		var pkBytes []byte
		pkBytes, err = hex.DecodeString(pubKeyStr)
		if err != nil {
			return
		}
		// TODO: use parameter instead of hard coding
		var pkInner crypto.PubKeySecp256k1
		copy(pkInner[:], pkBytes[:])
		pk = pkInner.Wrap()
		return
	} else if len(pubKeyStr) == 64 {
		var pkBytes []byte
		pkBytes, err = hex.DecodeString(pubKeyStr)
		if err != nil {
			return
		}
		// TODO: use parameter instead of hard coding
		var pkInner crypto.PubKeyEd25519
		copy(pkInner[:], pkBytes[:])
		pk = pkInner.Wrap()
		return
	} else {
		err = fmt.Errorf("PubKey len should be either 64 or 66, not", len(pubKeyStr))
		return
	}
}

func ParseFloat(str string) float64 {
	value, err := strconv.ParseFloat(str, 64)
	if err != nil {
		return 0
	}

	return value
}

func ParseInt(str string) *big.Int {
	value, ok := new(big.Int).SetString(str, 10)
	if !ok {
		return big.NewInt(0)
	}

	return value
}

func ToWei(value int64) (result *big.Int) {
	result = new(big.Int)
	result.Mul(big.NewInt(value), big.NewInt(1e18))
	return
}

func PubKeyString(pk crypto.PubKey) string {
	switch pki := pk.PubKeyInner.(type) {
	case crypto.PubKeyEd25519:
		return fmt.Sprintf("%X", pki[:])
	case crypto.PubKeySecp256k1:
		return fmt.Sprintf("%X", pki[:])
	default:
		return ""
	}
}

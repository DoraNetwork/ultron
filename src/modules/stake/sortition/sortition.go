package sortition

import (
	"fmt"
	"math/big"
	"encoding/hex"
	"errors"
	"github.com/tendermint/tendermint/vrf/utils"
)

var (
	ErrInvalidParams = errors.New("invalide params")
	HashMax, _, _ = new(big.Float).Parse("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
)

var (
	// cache to store binomial probabilities
	// key: n+p, value: related probabilities (0~n)
	probCache = make(map[float64]([]float64), 5)
)

// Simplified sortition algorithm implementation
// In original design, each candidate need to generate verifiable random
// based on their secret key before sortition. In this case, we need a
// round of consensus to make sure all candidates are honest.
// In the simplied vesion, we'll use ordinary SHA3-256 to generate random
// which is public and fair to everyone. However, candidate's public key
// and each block's VRF seed will be used as entropy sources.
//
// Params
//   key: candidate's public key
//   seed: block's VRF seed
//   t: each subuser's stake
//   s: size of subuser committee (to be nominated)
//   w: current candidate's stake
//   W: all candidates' total stake
// Returns
//   hash: generated random
//   j: nominated subuser number
func Sortition(key []byte, seed []byte, t, s, w, W uint64) (hash []byte, j uint) {
	hash = utils.Sha3256(key, seed)
	tao := t * s
	p := float64(tao) / float64(W)
	j = 0
	n := uint(w / t)

	hashVal, _, _ := new(big.Float).Parse(hex.EncodeToString(hash), 16)
	if hashVal != nil {
		lot, _ := new(big.Float).Quo(hashVal, HashMax).Float64()
		section := float64(0)
		for ; j <= n; j++ {
			section, _ = cumulativeBinomial(p, n, j)
			if lot <= section {
				break
			}
		}

		fmt.Printf("[j=%d]lot: %.2f, section: %.2f, hash: %v\n", j, lot, section, new(big.Int).SetBytes(hash))
	}

	return
}

func power(x float64, n uint) float64 {
	if n == 0 {
		return 1.0
	}
    return x * power(x, n - 1)
}

func factorial(n uint) uint {
	if n == 0 || n == 1 {
		return 1
	}
	return n * factorial(n - 1)
}

func singleBinomial(p float64, n, k uint) (float64, error) {
	if p <= 0 || p >= 1 || k > n {
		return 0, ErrInvalidParams
	}

	num := float64(factorial(n)) * power(p, k) * power(1 - p, n - k)
	den := float64(factorial(k) * factorial(n - k))
	return num / den, nil
}

func binomial(p float64, n uint) []float64 {
	probs := []float64{}
	for i := uint(0); i <= n; i++ {
		pi, _ := singleBinomial(p, n, i)
		probs = append(probs, pi)
	}

	return probs
}

func cumulativeBinomial(p float64, n, k uint) (float64, error) {
	if p <= 0 || p >= 1 || k > n {
		return 0, ErrInvalidParams
	}

	// use n+p as unique key for probCache
	key := float64(n) + p
	if _, ok := probCache[key]; !ok {
		probCache[key] = binomial(p, n)
	}

	probs := probCache[key]
	sum := 0.0
	for i := uint(0); i <= k; i++ {
		sum += probs[i]
	}

	return sum, nil
}

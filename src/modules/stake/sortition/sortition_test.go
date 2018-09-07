package sortition

import (
	"fmt"
	"encoding/hex"
	"testing"
	"github.com/tendermint/tendermint/types"
)

type Attendee struct {
	pubkey []byte
	power uint64
}

func TestBinomial(t *testing.T) {
	n := uint(20)
	p := 0.028
	fmt.Println(binomial(p, n))
}

func TestCumulativeBinomial(t *testing.T) {
	n := uint(20)
	p := 0.028
	for i := uint(0); i <= n; i++ {
		fmt.Println(cumulativeBinomial(p, n, i))
	}
}

func TestSortition(t1 *testing.T) {
	rounds := 200 // test rounds

	seed := types.GENESIS_SEED

	pubkey1, _ := hex.DecodeString("0F2560D7980F13A269341BB34AA6D471E8FBA13EFBC3B725C57CCBC02DB1FACD")
	pubkey2, _ := hex.DecodeString("C1D0F843FADAA9062C715BDC88B1AF00078D5D4DB699966D97F69774B7305B13")
	pubkey3, _ := hex.DecodeString("8D2DB44F1DEC776217C619374D8300B6AD95E7C7EAD6AC5D5C16CB4B787BFC61")
	attendees := []Attendee {
		Attendee{pubkey1, 2000},
		Attendee{pubkey2, 1000},
		Attendee{pubkey3, 500},
	}
	N := len(attendees)

	W := uint64(3500)
	t := uint64(100)
	s := uint64(10)

	statistics := make([]int, N)

	for i := 0; i < rounds; i++ {
		index := i % N
		// update VRF random per block
		random, _ := types.GenerateRandom(attendees[index].pubkey, seed)
		seed = random.Seed
		// nominate validators
		for k := 0; k < N; k++ {
			_, j := Sortition(seed, attendees[k].pubkey, t, s, attendees[k].power, W)
			statistics[k] += int(j)
		}
	}

	fmt.Println("=========== Summary ===========")

	total := rounds * int(s)
	for i := 0; i < N; i++ {
		fmt.Printf("[%d]stake: %d%%, nominated (%d / %d%%)\n",
			i,
			attendees[i].power * 100 / W,
			statistics[i],
			statistics[i] * 100 / total)
	}
}

package ethereum

import (
	"fmt"
	"sync"
	"time"
)

type TimeTrace struct {
	allAccumulatedCount map[string]int64
	allAccumulatedTime  map[string]int64

	accumulatedCount map[string]int64
	accumulatedTime  map[string]int64
	startTime        map[string]time.Time
	mtx              sync.Mutex
}

func NewTimeTrace() *TimeTrace {
	return &TimeTrace{
		accumulatedCount:    make(map[string]int64),
		accumulatedTime:     make(map[string]int64),
		allAccumulatedCount: make(map[string]int64),
		allAccumulatedTime:  make(map[string]int64),
		startTime:           make(map[string]time.Time),
	}
}

func (tt *TimeTrace) reset() {
	tt.mtx.Lock()
	defer tt.mtx.Unlock()
	tt.accumulatedCount = make(map[string]int64)
	tt.accumulatedTime = make(map[string]int64)
	tt.allAccumulatedCount = make(map[string]int64)
	tt.allAccumulatedTime = make(map[string]int64)
	tt.startTime = make(map[string]time.Time)
}

func (tt *TimeTrace) start(action string) {
	tt.mtx.Lock()
	defer tt.mtx.Unlock()
	tt.startTime[action] = time.Now()
}

func (tt *TimeTrace) endWithPrint(action string) {
	//duration := tt.end(action)
	//fmt.Println("action", action, "cost", duration/1000, "us")
}

func (tt *TimeTrace) end(action string) int64 {
	tt.mtx.Lock()
	defer tt.mtx.Unlock()
	if startTime, ok := tt.startTime[action]; ok {
		delete(tt.startTime, action)
		duration := time.Now().Sub(startTime).Nanoseconds()
		if _, ok := tt.accumulatedTime[action]; !ok {
			tt.accumulatedTime[action] = 0
			tt.accumulatedCount[action] = 0
		}
		tt.accumulatedTime[action] = tt.accumulatedTime[action] + duration
		tt.accumulatedCount[action] = tt.accumulatedCount[action] + 1
		return duration
	} else {
		fmt.Println("TimeTrace End error, No start time", action)
		return 0
	}
}

func (tt *TimeTrace) printAll() {
	tt.mtx.Lock()
	defer tt.mtx.Unlock()
	fmt.Println("+++++++one block++++++")
	var total int64 = 0
	for key, value := range tt.accumulatedTime {
		count := tt.accumulatedCount[key]

		if _, ok := tt.allAccumulatedTime[key]; !ok {
			tt.allAccumulatedTime[key] = 0
			tt.allAccumulatedCount[key] = 0
		}
		tt.allAccumulatedTime[key] += value
		tt.allAccumulatedCount[key] += count

		total += value
		fmt.Println(key, "totalCost", value/1000, "us", "totalCount", count, "average", value/count/1000, "us")
	}
	tt.accumulatedCount = make(map[string]int64)
	tt.accumulatedTime = make(map[string]int64)

	fmt.Println("Block totalCost", total/1000, "us")
	fmt.Println("+++++++++++++")

	fmt.Println("+++++++All++++++")
	total = 0
	for key, value := range tt.allAccumulatedTime {
		total += value
		fmt.Println(key, "totalCost", value/1000, "us", "totalCount", tt.allAccumulatedCount[key], "average", value/tt.allAccumulatedCount[key]/1000, "us")
	}
	fmt.Println("All totalCost", total/1000, "us")
	fmt.Println("+++++++++++++")
}

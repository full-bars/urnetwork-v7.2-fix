package connect

import (
	"sync/atomic"
	"time"
)

type logThrottle struct {
	intervalNanos int64
	lastNanos     atomic.Int64
	suppressed    atomic.Int64
}

func newLogThrottle(interval time.Duration) *logThrottle {
	return &logThrottle{intervalNanos: int64(interval)}
}

func (t *logThrottle) Allow(now time.Time) (bool, int64) {
	nowNanos := now.UnixNano()
	last := t.lastNanos.Load()
	if nowNanos-last < t.intervalNanos {
		t.suppressed.Add(1)
		return false, 0
	}
	if !t.lastNanos.CompareAndSwap(last, nowNanos) {
		t.suppressed.Add(1)
		return false, 0
	}
	return true, t.suppressed.Swap(0)
}

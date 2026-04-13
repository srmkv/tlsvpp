package client

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type DataplaneSnapshot struct {
	InterfaceName   string
	StartedAt       string
	LastFrameAt     string
	LastError       string
	TunReads        uint64
	TunReadBytes    uint64
	FramePosts      uint64
	FramePostErrors uint64
	Keepalives      uint64
	KeepaliveErrors uint64
	PollRequests    uint64
	PollFrames      uint64
	PollErrors      uint64
	TunWrites       uint64
	TunWriteBytes   uint64
}

type dataplaneCounters struct {
	TunReads        atomic.Uint64
	TunReadBytes    atomic.Uint64
	FramePosts      atomic.Uint64
	FramePostErrors atomic.Uint64
	Keepalives      atomic.Uint64
	KeepaliveErrors atomic.Uint64
	PollRequests    atomic.Uint64
	PollFrames      atomic.Uint64
	PollErrors      atomic.Uint64
	TunWrites       atomic.Uint64
	TunWriteBytes   atomic.Uint64
}

var (
	dataplaneStateMu sync.RWMutex
	dataplaneState   struct {
		InterfaceName string
		StartedAt     time.Time
		LastFrameAt   time.Time
		LastError     string
	}
	dataplaneCtrs dataplaneCounters
)

func resetDataplaneSnapshot(iface string) {
	dataplaneStateMu.Lock()
	dataplaneState.InterfaceName = strings.TrimSpace(iface)
	dataplaneState.StartedAt = time.Now().UTC()
	dataplaneState.LastFrameAt = time.Time{}
	dataplaneState.LastError = ""
	dataplaneStateMu.Unlock()
	dataplaneCtrs = dataplaneCounters{}
}

func dataplaneMarkFrame() {
	dataplaneStateMu.Lock()
	dataplaneState.LastFrameAt = time.Now().UTC()
	dataplaneStateMu.Unlock()
}

func dataplaneMarkError(err error) {
	if err == nil {
		return
	}
	dataplaneStateMu.Lock()
	dataplaneState.LastError = strings.TrimSpace(err.Error())
	dataplaneStateMu.Unlock()
}

func SnapshotDataplane() DataplaneSnapshot {
	dataplaneStateMu.RLock()
	st := dataplaneState
	dataplaneStateMu.RUnlock()
	return DataplaneSnapshot{
		InterfaceName:   st.InterfaceName,
		StartedAt:       timeToRFC3339(st.StartedAt),
		LastFrameAt:     timeToRFC3339(st.LastFrameAt),
		LastError:       st.LastError,
		TunReads:        dataplaneCtrs.TunReads.Load(),
		TunReadBytes:    dataplaneCtrs.TunReadBytes.Load(),
		FramePosts:      dataplaneCtrs.FramePosts.Load(),
		FramePostErrors: dataplaneCtrs.FramePostErrors.Load(),
		Keepalives:      dataplaneCtrs.Keepalives.Load(),
		KeepaliveErrors: dataplaneCtrs.KeepaliveErrors.Load(),
		PollRequests:    dataplaneCtrs.PollRequests.Load(),
		PollFrames:      dataplaneCtrs.PollFrames.Load(),
		PollErrors:      dataplaneCtrs.PollErrors.Load(),
		TunWrites:       dataplaneCtrs.TunWrites.Load(),
		TunWriteBytes:   dataplaneCtrs.TunWriteBytes.Load(),
	}
}

func timeToRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func ClearDataplaneSnapshot() {
	dataplaneStateMu.Lock()
	dataplaneState.InterfaceName = ""
	dataplaneState.StartedAt = time.Time{}
	dataplaneState.LastFrameAt = time.Time{}
	dataplaneState.LastError = ""
	dataplaneStateMu.Unlock()
	dataplaneCtrs = dataplaneCounters{}
}

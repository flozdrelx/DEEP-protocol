// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// Server limits are local operational policy, not negotiated wire capabilities.
func (s Server) configured() (Server, error) {
	if s.Timeout < 0 || s.HandshakeTimeout < 0 || s.IdleTimeout < 0 || s.SessionTimeout < 0 ||
		s.MaxConnections < 0 || s.MaxConnectionsPerPeer < 0 || s.MaxBytes < 0 || s.RequestsPerMinute < 0 {
		return s, errors.New("server limits cannot be negative")
	}
	if s.Timeout == 0 {
		s.Timeout = 30 * time.Second
	}
	if s.HandshakeTimeout == 0 {
		s.HandshakeTimeout = 5 * time.Second
	}
	if s.IdleTimeout == 0 {
		s.IdleTimeout = 30 * time.Second
	}
	if s.SessionTimeout == 0 {
		s.SessionTimeout = 5 * time.Minute
	}
	if s.MaxConnections == 0 {
		s.MaxConnections = 64
	}
	if s.MaxConnectionsPerPeer == 0 {
		s.MaxConnectionsPerPeer = min(16, s.MaxConnections)
	}
	if s.MaxRequestsPerSession == 0 {
		s.MaxRequestsPerSession = 128
	}
	if s.MaxBytes == 0 {
		s.MaxBytes = DefaultMaxBytes
	}
	if s.RequestsPerMinute == 0 {
		s.RequestsPerMinute = 120
	}
	if s.MaxConnections > 4096 || s.MaxConnectionsPerPeer > s.MaxConnections ||
		s.MaxRequestsPerSession > 1000000 || s.MaxBytes > MaxResourceSize ||
		s.RequestsPerMinute > 1000000 || s.HandshakeTimeout > time.Minute ||
		s.IdleTimeout > time.Hour || s.Timeout > time.Hour || s.SessionTimeout > 24*time.Hour {
		return s, errors.New("server limits exceed supported bounds")
	}
	return s, nil
}

const maxTrackedPeers = 4096
const maxConnectionsPerPeerMinute = 240

type peerBudget struct {
	active                int
	window                time.Time
	connections, requests int
}

// Entries include recently disconnected peers so reconnecting does not reset
// rate limits. The map is bounded and evicts only inactive, expired entries.
type peerLimiter struct {
	mu                sync.Mutex
	peers             map[string]*peerBudget
	maximum, requests int
	lastPrune         time.Time
}

func newPeerLimiter(maximum, requests int) *peerLimiter {
	return &peerLimiter{peers: make(map[string]*peerBudget), maximum: maximum, requests: requests}
}

func peerKey(address net.Addr) string {
	if address == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(address.String())
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		return strings.ToLower(host)
	}
	// Custom transports must return a stable peer identifier, not a random
	// connection ID, for this per-peer policy to provide isolation.
	key := address.Network() + ":" + address.String()
	if len(key) > 256 {
		return "unknown"
	}
	return key
}

func (l *peerLimiter) acquire(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	budget := l.peers[key]
	if budget == nil {
		if len(l.peers) >= maxTrackedPeers {
			if now.Sub(l.lastPrune) >= time.Second {
				for name, candidate := range l.peers {
					if candidate.active == 0 && now.Sub(candidate.window) >= time.Minute {
						delete(l.peers, name)
					}
				}
				l.lastPrune = now
			}
			if len(l.peers) >= maxTrackedPeers {
				return false
			}
		}
		budget = &peerBudget{window: now}
		l.peers[key] = budget
	}
	resetBudget(budget, now)
	if budget.active >= l.maximum || budget.connections >= maxConnectionsPerPeerMinute {
		return false
	}
	budget.active++
	budget.connections++
	return true
}

func resetBudget(b *peerBudget, now time.Time) {
	if now.Sub(b.window) >= time.Minute {
		b.window, b.connections, b.requests = now, 0, 0
	}
}

func (l *peerLimiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.peers[key]; b != nil && b.active > 0 {
		b.active--
	}
}

func (l *peerLimiter) allowRequest(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.peers[key]
	if b == nil {
		return false
	}
	resetBudget(b, now)
	if b.requests >= l.requests {
		return false
	}
	b.requests++
	return true
}

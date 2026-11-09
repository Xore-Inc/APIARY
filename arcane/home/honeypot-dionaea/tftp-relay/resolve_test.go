package main

import (
	"errors"
	"net"
	"testing"
	"time"
)

func udp(a string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp4", a)
	if err != nil {
		panic(err)
	}
	return addr
}

// #3593: dionaea is a swarm task in endpoint_mode dnsrr, so a replaced task
// comes back on a new overlay address. A new session must follow it.
func TestSessionTargetFollowsReResolution(t *testing.T) {
	answers := []string{"10.200.28.3:69", "10.200.28.7:69"}
	calls := 0
	r := &relay{resolve: func() (*net.UDPAddr, error) {
		a := answers[calls]
		if calls < len(answers)-1 {
			calls++
		}
		return udp(a), nil
	}}
	if got := r.sessionTarget(); got.String() != "10.200.28.3:69" {
		t.Fatalf("first target = %v", got)
	}
	if got := r.sessionTarget(); got.String() != "10.200.28.7:69" {
		t.Fatalf("after re-resolution target = %v, want the new task address", got)
	}
}

func TestSessionTargetCachesWithinResolveEvery(t *testing.T) {
	calls := 0
	r := &relay{resolveEvery: time.Hour, resolve: func() (*net.UDPAddr, error) {
		calls++
		return udp("10.200.28.3:69"), nil
	}}
	for i := 0; i < 5; i++ {
		r.sessionTarget()
	}
	if calls != 1 {
		t.Fatalf("resolver called %d times within resolveEvery, want 1", calls)
	}
}

// A failed lookup must never be worse than resolving once at start.
func TestSessionTargetKeepsLastGoodOnFailure(t *testing.T) {
	fail := false
	r := &relay{resolve: func() (*net.UDPAddr, error) {
		if fail {
			return nil, errors.New("no such host")
		}
		return udp("10.200.28.3:69"), nil
	}}
	r.sessionTarget()
	fail = true
	if got := r.sessionTarget(); got == nil || got.String() != "10.200.28.3:69" {
		t.Fatalf("target after failed lookup = %v, want the last good address", got)
	}
}

// Never resolved: the datagram is dropped and no session (socket +
// goroutine) is opened; the client's TFTP retry gets the next attempt.
func TestHandleDatagramDropsWhileTargetUnresolved(t *testing.T) {
	r := &relay{
		maxSessions: 4,
		listenPort:  1069,
		server:      &recordingUpstream{},
		sessions:    map[string]*session{},
		resolve:     func() (*net.UDPAddr, error) { return nil, errors.New("no such host") },
	}
	r.handleDatagram([]byte("RRQ"), clientAddr())
	if len(r.sessions) != 0 {
		t.Fatalf("opened %d sessions without a target", len(r.sessions))
	}
}

// A new session starts at the freshly resolved address, not the one cached
// before the task moved.
func TestHandleDatagramNewSessionUsesCurrentTarget(t *testing.T) {
	r := &relay{
		maxSessions: 4,
		listenPort:  1069,
		server:      &recordingUpstream{},
		sessions:    map[string]*session{},
		target:      udp("10.200.28.3:69"),
		resolve:     func() (*net.UDPAddr, error) { return udp("127.0.0.1:9"), nil },
	}
	r.handleDatagram([]byte("RRQ"), clientAddr())
	s := r.sessions[clientAddr().String()]
	if s == nil {
		t.Fatal("no session opened")
	}
	defer s.conn.Close()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.target.String() != "127.0.0.1:9" {
		t.Fatalf("session target = %v, want the re-resolved address", s.target)
	}
}

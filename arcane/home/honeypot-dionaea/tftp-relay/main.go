package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// udpReplyWriter is the slice of an upstream socket the forwarding paths
// actually need -- narrowed to an interface so handler_panic_test.go can
// hand the relay a crafted socket whose reply leg detonates mid-handler
// (see #2489); the real *net.UDPConn main() opens satisfies it as-is.
type udpReplyWriter interface {
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	SetReadDeadline(t time.Time) error
}

// upstreamConn adds the read/close legs relayReplies needs off the same
// underlying socket -- still narrow enough to craft, nothing more than
// main()'s real conn offers.
type upstreamConn interface {
	udpReplyWriter
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	Close() error
}

// replySink is the listener-facing half of the forwarding story --
// relayReplies sends every upstream datagram back toward the client through
// it. Narrowed like udpReplyWriter so the crafted sockets can detonate the
// exact leg a handler exercises (#2489); the real listener satisfies it as-is.
type replySink interface {
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
}

type session struct {
	conn   upstreamConn
	mu     sync.RWMutex
	target *net.UDPAddr
}

// relay bundles what every per-datagram and per-session hop needs, so the
// handlers can be plain methods instead of six-parameter functions whose
// callers (and tests) have to keep the argument order straight (#2489).
type relay struct {
	server replySink
	// target is where a NEW session sends its first datagram. With resolve
	// set it is refreshed from TFTP_TARGET at most every resolveEvery (#3593):
	// dionaea runs as a swarm task in endpoint_mode dnsrr, and every task
	// replacement gives it a new overlay address. Resolving once at start
	// left the relay forwarding to a dead address until it was restarted.
	target         *net.UDPAddr
	targetMu       sync.Mutex
	resolve        func() (*net.UDPAddr, error)
	resolveEvery   time.Duration
	resolvedAt     time.Time
	resolveFailed  bool
	maxSessions    int
	sessionLog     *os.File
	sessionLogPath string
	sessionLogSize int64
	sessionLogMax  int64
	sessionLogMu   sync.Mutex
	listenPort     int
	lock           sync.Mutex
	sessions       map[string]*session
}

func main() {
	listen := getenv("LISTEN_ADDR", ":1069")
	targetSpec := getenv("TFTP_TARGET", "dionaea:69")
	resolve := func() (*net.UDPAddr, error) { return net.ResolveUDPAddr("udp4", targetSpec) }
	// Not fatal (#3593): the target is a swarm task that can start after this
	// container (host boot, task replacement). Until it resolves, datagrams
	// are dropped and the client's own TFTP retry gets the next attempt.
	target, err := resolve()
	if err != nil {
		log.Printf("tftp relay: target %s not resolvable yet, retrying per session: %v", targetSpec, err)
	}
	server, err := net.ListenUDP("udp4", mustAddr(listen))
	if err != nil {
		log.Fatal(err)
	}
	sessionLogPath := getenv("SESSION_LOG", "/logs/sessions.json")
	sessionLog := openSessionLog(sessionLogPath)
	if sessionLog != nil {
		defer sessionLog.Close()
	}
	var sessionLogSize int64
	if sessionLog != nil {
		if st, err := sessionLog.Stat(); err == nil {
			sessionLogSize = st.Size()
		}
	}
	// #882: UDP has no handshake, so a source (client) address on an
	// incoming datagram is trivially spoofable, and every not-yet-seen one
	// opened a brand new outbound socket + goroutine with no admission
	// control -- a burst of single-packet requests with spoofed sources
	// could exhaust the process's file-descriptor limit well before the
	// existing 2-minute idle sweep in relayReplies ever ran.
	maxSessions := getenvInt("TFTP_MAX_SESSIONS", 1024)
	log.Printf("tftp relay %s -> %s %v (max %d concurrent sessions)", listen, targetSpec, target, maxSessions)
	r := &relay{
		server:         server,
		target:         target,
		resolve:        resolve,
		resolveEvery:   time.Duration(getenvInt("TFTP_RESOLVE_SECONDS", 5)) * time.Second,
		resolvedAt:     time.Now(),
		resolveFailed:  err != nil,
		maxSessions:    maxSessions,
		sessionLog:     sessionLog,
		sessionLogPath: sessionLogPath,
		sessionLogSize: sessionLogSize,
		sessionLogMax:  getenvInt64("LOG_MAX_BYTES", 67108864),
		listenPort:     server.LocalAddr().(*net.UDPAddr).Port,
		sessions:       map[string]*session{},
	}
	buf := make([]byte, 65535)
	for {
		n, client, readErr := server.ReadFromUDP(buf)
		if readErr != nil {
			continue
		}
		r.handleDatagram(buf[:n], client)
	}
}

func (r *relay) handleDatagram(datagram []byte, client *net.UDPAddr) {
	// #2489: handleDatagram is the whole world past ReadFromUDP -- attacker
	// datagrams hit the session table and the upstream write with no recover
	// anywhere downstream, and in Go one unrecovered panic kills the entire
	// relay while restart: unless-stopped hands the attacker the same
	// replayable datagram right back. The forwarding itself is bounds-free
	// today, but the boundary exists for what future edits past it could
	// add: a panicking datagram costs exactly one attributable handler_panic
	// event while the ReadFromUDP loop and every other live session keep
	// running.
	defer func() {
		if rec := recover(); rec != nil {
			emitPanic(r.listenPort, client, rec)
		}
	}()
	key := client.String()
	r.lock.Lock()
	current := r.sessions[key]
	r.lock.Unlock()
	var target *net.UDPAddr
	if current == nil {
		// Resolved outside the session-table lock: a slow lookup must not
		// stall datagrams of sessions that already exist.
		if target = r.sessionTarget(); target == nil {
			return
		}
	}
	r.lock.Lock()
	current = r.sessions[key]
	if current == nil {
		if len(r.sessions) >= r.maxSessions {
			// At the cap: drop rather than open another upstream
			// socket/goroutine. A real client just retries (TFTP is
			// itself a retry-on-timeout protocol); an attacker's
			// spoofed-source flood gets no further sockets to burn.
			r.lock.Unlock()
			return
		}
		upstream, listenErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if listenErr != nil {
			r.lock.Unlock()
			return
		}
		// #747: dionaea sees every TFTP session as coming from this
		// relay's own upstream socket, never the real client -- its
		// own connection log has no way to recover client.IP once the
		// packet leaves this process. Recording {relay_port, client_ip}
		// the moment that socket is opened (this port is exactly what
		// dionaea will log as src_port for the resulting session, per
		// TFTP's own "server replies from a fresh ephemeral port, but
		// the client's own port stays fixed for the session" contract)
		// lets ip-enrichment-worker join on it the same way it already
		// joins portbridge's via_port for every other affected sensor.
		r.logSession(upstream.LocalAddr().(*net.UDPAddr).Port, client.IP.String())
		current = &session{conn: upstream, target: target}
		r.sessions[key] = current
		go r.relayReplies(client, key, current)
	}
	r.lock.Unlock()
	current.mu.RLock()
	peer := current.target
	current.mu.RUnlock()
	current.conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
	_, _ = current.conn.WriteToUDP(datagram, peer)
}

// sessionTarget returns the address a new session starts at: the cached
// resolution of TFTP_TARGET, refreshed once it is older than resolveEvery. A
// failed lookup keeps the last good address (never worse than resolving once
// at start); nil only while the target has never resolved.
func (r *relay) sessionTarget() *net.UDPAddr {
	r.targetMu.Lock()
	defer r.targetMu.Unlock()
	if r.resolve == nil || (r.target != nil && time.Since(r.resolvedAt) < r.resolveEvery) {
		return r.target
	}
	addr, err := r.resolve()
	r.resolvedAt = time.Now()
	if err != nil {
		if !r.resolveFailed {
			log.Printf("tftp relay: target lookup failed, keeping %v: %v", r.target, err)
		}
		r.resolveFailed = true
		return r.target
	}
	r.resolveFailed = false
	if r.target == nil || !addr.IP.Equal(r.target.IP) || addr.Port != r.target.Port {
		log.Printf("tftp relay: target now %s (was %v)", addr, r.target)
		r.target = addr
	}
	return r.target
}

func (r *relay) relayReplies(client *net.UDPAddr, key string, current *session) {
	buf := make([]byte, 65535)
	for {
		n, peer, err := current.conn.ReadFromUDP(buf)
		if err != nil {
			r.lock.Lock()
			delete(r.sessions, key)
			r.lock.Unlock()
			_ = current.conn.Close()
			return
		}
		// #2489: the boundary wraps the LOOP BODY, not the whole function --
		// recovering around the whole goroutine would contain the panic but
		// skip straight past the error-path cleanup that deletes the session
		// entry, and after #882's hard cap a leaked entry is a permanently
		// burned slot. A contained iteration leaves the table intact for the
		// next packet to reconnect or the sweep to reclaim.
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					emitPanic(r.listenPort, client, rec)
				}
			}()
			current.mu.Lock()
			current.target = peer
			current.mu.Unlock()
			_, _ = r.server.WriteToUDP(buf[:n], client)
		}()
	}
}

// panicOut is where handler_panic events land -- stdout, docker-captured and
// shape-compatible with every other sensor's JSON stream (jq-greppable as
// .event=="handler_panic") -- deliberately NOT sessions.json: that file is
// ip-enrichment-worker's {relay_port, client_ip} join contract from #747 and
// must stay exactly that shape.
var panicOut io.Writer = os.Stdout

func emitPanic(listenPort int, client *net.UDPAddr, recovered any) {
	line, err := json.Marshal(map[string]any{
		"time":     time.Now().UTC().Format(time.RFC3339),
		"sensor":   "tftp-relay",
		"proto":    "tftp",
		"port":     listenPort,
		"src_ip":   client.IP.String(),
		"src_port": client.Port,
		"event":    "handler_panic",
		"data":     fmt.Sprint(recovered),
	})
	if err != nil {
		return
	}
	fmt.Fprintln(panicOut, string(line))
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if n, err := strconv.Atoi(value); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func mustAddr(value string) *net.UDPAddr {
	address, err := net.ResolveUDPAddr("udp4", value)
	if err != nil {
		log.Fatal(err)
	}
	return address
}

// openSessionLog opens the session log for appending. Returns nil (not a
// fatal error) if the path can't be opened -- logging every real TFTP
// session's attribution is important but must never be why the relay
// itself refuses to start or stops forwarding traffic.
func openSessionLog(path string) *os.File {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		log.Printf("tftp relay: session log %s unavailable, continuing without it: %v", path, err)
		return nil
	}
	return f
}

func (r *relay) logSession(relayPort int, clientIP string) {
	if r.sessionLog == nil {
		return
	}
	line, err := json.Marshal(map[string]any{
		"relay_port": relayPort,
		"client_ip":  clientIP,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return
	}
	line = append(line, '\n')
	r.sessionLogMu.Lock()
	defer r.sessionLogMu.Unlock()
	if r.sessionLog == nil {
		return
	}
	if r.sessionLogMax > 0 && r.sessionLogSize >= r.sessionLogMax {
		r.rotateSessionLog()
	}
	if r.sessionLog != nil {
		n, _ := r.sessionLog.Write(line)
		r.sessionLogSize += int64(n)
	}
}

// rotateSessionLog closes the current session log, renames it aside with a
// timestamp suffix, and reopens a fresh file at the original path -- #120's
// contract, ported from multipot's logger (see that package's rotate() for
// the full reasoning). Callers must hold r.sessionLogMu.
func (r *relay) rotateSessionLog() {
	if r.sessionLog == nil || r.sessionLogPath == "" {
		return
	}
	r.sessionLog.Close()
	target := r.sessionLogPath + "." + time.Now().UTC().Format("20060102-150405")
	if _, err := os.Stat(target); err == nil {
		for n := 2; ; n++ {
			candidate := fmt.Sprintf("%s.%d", target, n)
			if _, err := os.Stat(candidate); err != nil {
				target = candidate
				break
			}
		}
	}
	os.Rename(r.sessionLogPath, target)
	f, err := os.OpenFile(r.sessionLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		r.sessionLog = nil
		log.Printf("tftp relay: session log %s unavailable after rotation: %v", r.sessionLogPath, err)
		return
	}
	r.sessionLog = f
	r.sessionLogSize = 0
}

func getenvInt64(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

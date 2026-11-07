package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// serveWith newHandler starts an httptest upstream and returns exactly the
// handler main() would serve against it -- no re-implemented copy lives
// here, so a change to production behavior changes what these tests see.
func newRealHandler(t *testing.T, upstream *httptest.Server, maxBody int64, upstreamTimeout time.Duration) http.Handler {
	t.Helper()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	return newHandler(target, maxBody, upstreamTimeout, defaultMaxInflight)
}

func TestAllowedPathIsForwarded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("upstream got path %q, want /api/chat", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("upstream Content-Type = %q, want application/json", got)
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Write([]byte(`{"message":"ok"}`))
	}))
	defer upstream.Close()

	h := newRealHandler(t, upstream, 65536, 8*time.Second)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"model":"qwen3:8b"}`))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != `{"message":"ok"}` {
		t.Fatalf("body = %q", rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/x-ndjson" {
		t.Errorf("relayed Content-Type = %q, want application/x-ndjson", got)
	}
}

func TestDisallowedPathIs404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should never be called for a disallowed path")
	}))
	defer upstream.Close()

	h := newRealHandler(t, upstream, 65536, 8*time.Second)
	for _, path := range []string{"/api/embeddings", "/api/pull", "/api/tags", "/"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("path %q: status = %d, want 404", path, rr.Code)
		}
	}
}

func TestGetIsRejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should never be called for GET")
	}))
	defer upstream.Close()

	h := newRealHandler(t, upstream, 65536, 8*time.Second)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/chat", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestOversizedBodyIsRejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should never be called for an oversized body")
	}))
	defer upstream.Close()

	h := newRealHandler(t, upstream, 16, 8*time.Second)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/generate", strings.NewReader(strings.Repeat("a", 1000)))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rr.Code)
	}
}

func TestEnvIntOrParsesOrFallsBack(t *testing.T) {
	if got := envIntOr("GALAH_BROKER_TEST_UNSET_VAR", 8); got != 8 {
		t.Fatalf("envIntOr fallback = %d, want 8", got)
	}
	t.Setenv("GALAH_BROKER_TEST_SET_VAR", "42")
	if got := envIntOr("GALAH_BROKER_TEST_SET_VAR", 8); got != 42 {
		t.Fatalf("envIntOr set = %d, want 42", got)
	}
	t.Setenv("GALAH_BROKER_TEST_BAD_VAR", "not-a-number")
	if got := envIntOr("GALAH_BROKER_TEST_BAD_VAR", 8); got != 8 {
		t.Fatalf("envIntOr bad-value fallback = %d, want 8", got)
	}
}

func TestUpstreamTimeoutSurfacesAsBadGateway(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte("too slow"))
	}))
	defer upstream.Close()

	// This drives the real request construction -- NewRequestWithContext on
	// the shared client -- so a regression in its timeout wiring fails here.
	h := newRealHandler(t, upstream, 65536, 5*time.Millisecond)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/generate", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 on upstream timeout", rr.Code)
	}
}

func TestResponseRelayKeepsUpstreamStatus(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"model not found"}`, http.StatusNotFound)
	}))
	defer upstream.Close()

	h := newRealHandler(t, upstream, 65536, 8*time.Second)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{}`))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 relayed from upstream", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "model not found") {
		t.Fatalf("body = %q, want upstream error body relayed", rr.Body.String())
	}
}

// holdingUpstream answers only when released, and records when the inbound
// request's context ends, which is how a cancelled broker request shows up.
type holdingUpstream struct {
	*httptest.Server
	entered   chan struct{}
	release   chan struct{}
	cancelled chan struct{}
}

func newHoldingUpstream(t *testing.T) *holdingUpstream {
	t.Helper()
	u := &holdingUpstream{
		entered:   make(chan struct{}, 16),
		release:   make(chan struct{}),
		cancelled: make(chan struct{}, 16),
	}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the body first: the server only notices a closed connection
		// (and cancels r.Context) once the request has been consumed.
		io.Copy(io.Discard, r.Body)
		u.entered <- struct{}{}
		select {
		case <-u.release:
			w.Write([]byte(`{"ok":true}`))
		case <-r.Context().Done():
			u.cancelled <- struct{}{}
		}
	}))
	t.Cleanup(u.Close)
	return u
}

func postChat(h http.Handler, ctx context.Context) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"model":"m"}`)).WithContext(ctx)
	h.ServeHTTP(rr, req)
	return rr
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestInflightCapAnswers503WhenFullAndFreesTheSlotOnCompletion(t *testing.T) {
	up := newHoldingUpstream(t)
	target, _ := url.Parse(up.URL)
	h := newHandler(target, 65536, 8*time.Second, 2)

	done := make(chan *httptest.ResponseRecorder, 2)
	for i := 0; i < 2; i++ {
		go func() { done <- postChat(h, context.Background()) }()
	}
	waitFor(t, up.entered, "first request to reach upstream")
	waitFor(t, up.entered, "second request to reach upstream")

	// Both slots are taken: the third must be refused at once, not queued.
	start := time.Now()
	rr := postChat(h, context.Background())
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when the cap is full", rr.Code)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("503 took %s, it must not wait on the upstream", time.Since(start))
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("503 should carry Retry-After")
	}
	select {
	case <-up.entered:
		t.Fatal("a refused request must never reach the upstream")
	default:
	}

	// Complete the two in-flight requests; the slots must come back.
	close(up.release)
	for i := 0; i < 2; i++ {
		if got := (<-done).Code; got != http.StatusOK {
			t.Fatalf("in-flight request status = %d, want 200", got)
		}
	}
	if rr := postChat(h, context.Background()); rr.Code != http.StatusOK {
		t.Fatalf("after completion status = %d, want 200 (slot not freed)", rr.Code)
	}
}

func TestCancelledClientFreesItsSlotAndCancelsTheUpstreamCall(t *testing.T) {
	up := newHoldingUpstream(t)
	target, _ := url.Parse(up.URL)
	h := newHandler(target, 65536, 30*time.Second, 1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { postChat(h, ctx); close(done) }()
	waitFor(t, up.entered, "request to reach upstream")

	if rr := postChat(h, context.Background()); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 while the only slot is held", rr.Code)
	}

	cancel() // the attacker's client went away
	waitFor(t, up.cancelled, "upstream request to be cancelled")
	waitFor(t, done, "cancelled handler to return")

	close(up.release)
	if rr := postChat(h, context.Background()); rr.Code != http.StatusOK {
		t.Fatalf("after cancellation status = %d, want 200 (slot leaked)", rr.Code)
	}
}

func TestNonPositiveCapDisablesTheLimit(t *testing.T) {
	up := newHoldingUpstream(t)
	close(up.release)
	target, _ := url.Parse(up.URL)
	h := newHandler(target, 65536, 8*time.Second, 0)
	for i := 0; i < 8; i++ {
		if rr := postChat(h, context.Background()); rr.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, rr.Code)
		}
	}
}

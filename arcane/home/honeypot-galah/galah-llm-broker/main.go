// galah-llm-broker is the sole bridge between the attacker-facing galah
// sensor and the shared Ollama instance on the honeypot-llm network (see
// analysis/ghidra/docker-compose.ghidra.yml's own "sensors must never be
// able to submit prompts or observe model traffic" invariant -- galah's
// container is deliberately never attached to that network itself).
//
// It proxies exactly the two Ollama routes langchaingo's ollama client
// calls (confirmed against the vendored client source, not assumed):
// /api/generate and /api/chat. Everything else 404s. Request bodies are
// capped and upstream calls are time-bounded so an attacker-controlled
// HTTP request (which becomes the entire LLM prompt verbatim -- galah's
// own llm.CreateMessageContent dumps the raw request into the prompt with
// no size limit of its own) can't turn into unbounded prompt size or a
// stuck request against the shared GPU backend.
package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

// defaultMaxInflight is deliberately small: galah caches responses, so the
// broker sees only first-time request shapes, and a model on one GPU serves
// a handful of them at once at best. Anything past this is better refused
// than queued (#3666).
const defaultMaxInflight = 4

var allowedPaths = map[string]bool{
	"/api/generate": true,
	"/api/chat":     true,
}

func main() {
	target := envOr("OLLAMA_URL", "http://ollama:11434")
	listen := envOr("LISTEN_ADDR", ":11434")
	maxBody := envIntOr("MAX_BODY_BYTES", 65536)
	upstreamTimeout := time.Duration(envIntOr("UPSTREAM_TIMEOUT_SECONDS", 8)) * time.Second
	// #3666: bounded concurrency towards Ollama. 0 or negative disables the
	// cap (the pre-#3666 behaviour).
	maxInflight := envIntOr("MAX_INFLIGHT", defaultMaxInflight)

	targetURL, err := url.Parse(target)
	if err != nil {
		log.Fatalf("galah-llm-broker: invalid OLLAMA_URL %q: %s", target, err)
	}

	log.Printf("galah-llm-broker: listening on %s, forwarding to %s (max body %d bytes, upstream timeout %s, max in-flight %d)", listen, target, maxBody, upstreamTimeout, maxInflight)
	log.Fatal(http.ListenAndServe(listen, newHandler(targetURL, int64(maxBody), upstreamTimeout, maxInflight)))
}

// newHandler builds the proxy main() serves. It lives outside main() so
// the test suite exercises this exact construction rather than its own
// re-implemented copy; editing it is what changes broker behavior.
//
// It is also the only place in the stack that still holds the prompt text
// after galah has handed the attacker's raw request to the model and before
// galah has thrown it away, so prompt-injection classification runs here
// (#3448; see injection.go). Classification is read-only: body is forwarded
// as the exact bytes galah sent, and neither the status nor the body this
// handler relays is influenced by what the classifier found.
//
// maxInflight bounds how many requests are being forwarded to Ollama at
// once (#3666). Ollama queues what it cannot run yet, and a client that
// gives up does not shorten that queue: requests sat behind a benchmark for
// over ten hours. So when every slot is taken the next request is answered
// at once with 503 instead of joining the queue. A slot is held from
// admission until the handler returns, and the upstream request carries the
// inbound request's context, so a client that disconnects cancels the
// upstream call and frees its slot immediately. maxInflight <= 0 disables
// the cap.
func newHandler(target *url.URL, maxBody int64, upstreamTimeout time.Duration, maxInflight int) http.Handler {
	client := &http.Client{Timeout: upstreamTimeout}
	injection := injectionShapesFromEnv()
	var slots chan struct{}
	if maxInflight > 0 {
		slots = make(chan struct{}, maxInflight)
	}
	var rejected atomic.Int64
	var lastLog atomic.Int64

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !allowedPaths[r.URL.Path] {
			http.NotFound(w, r)
			return
		}

		if slots != nil {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				n := rejected.Add(1)
				// An attacker can drive this path, so log at most once a
				// second, with the number refused since the last line.
				now := time.Now().Unix()
				if last := lastLog.Load(); last != now && lastLog.CompareAndSwap(last, now) {
					log.Printf("galah-llm-broker: saturated, refusing with 503 (all %d slots in flight, %d refused so far)", cap(slots), n)
				}
				w.Header().Set("Retry-After", "5")
				http.Error(w, "llm backend saturated", http.StatusServiceUnavailable)
				return
			}
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}

		// Read-only, and before the upstream call so a hit is recorded
		// whether or not the model ever answers. body itself is not
		// modified -- classifyForwardedPrompt decodes into its own struct
		// and the same slice is what goes upstream below.
		if label, carrier := classifyForwardedPrompt(body); label != "" {
			logPromptInjection(label, carrier, body, injection)
		}

		ctx, cancel := context.WithTimeout(r.Context(), upstreamTimeout)
		defer cancel()

		upstreamURL := *target
		upstreamURL.Path = r.URL.Path
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL.String(), bytes.NewReader(body))
		if err != nil {
			http.Error(w, "bad upstream request", http.StatusInternalServerError)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "" {
			req.Header.Set("Content-Type", ct)
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("galah-llm-broker: upstream error: %s", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
	return mux
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

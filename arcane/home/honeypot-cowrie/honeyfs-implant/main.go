// honeyfs-implant -- #1487: plants a file into Cowrie's live, bind-mounted
// honeyfs (arcane/home/honeypot-cowrie/compose.yml's honeyfs mount, shared
// with the cowrie service itself) so a dashboard-created token or
// credential shows up in the running persona's fake filesystem without a
// rebuild/redeploy.
//
// This service deliberately does NOT touch fs.pickle itself. Writing bytes
// to disk alone would not be enough for cowrie to actually serve the file
// (see cowrie/bin/sync-fs.py's own docstring: `ls` reads fs.pickle, `cat`
// reads honeyfs, and only sync-fs.py keeps the two in agreement) -- but
// cowrie's own entrypoint.sh already reruns sync-fs.py unconditionally on
// every boot, and setImplantPending's marker guarantees a boot happens
// right after every implant (see below). A second sync-fs.py run here
// would be redundant and, worse, would record this container's own mount
// path (/data/honeyfs) as fs.pickle's A_REALFILE instead of cowrie's
// (/cowrie/cowrie-git/honeyfs) -- wrong for cowrie to read, even though
// cowrie's next restart harmlessly overwrites it before ever loading the
// pickle (fs.pickle is read once at cowrie's own process startup, never
// polled live). Simpler to just not write it in the first place.
//
// WireGuard-tunnel-only (matches every other internal-only API in this
// repo's posture, e.g. canarytokens_client.go's own CANARYTOKENS_API_URL)
// -- the dashboard's own backend is the only intended caller.
//
// This service never touches Docker in any way. It writes a file and
// drops an implant-pending marker; cowrie's own HEALTHCHECK (compose.yml)
// fails while that marker exists, and the already-deployed autoheal
// service (honeypot-utilities/compose.yml, talking only to
// docker-socket-proxy, never the raw socket) restarts cowrie on the next
// unhealthy check. entrypoint.sh clears the marker (and re-syncs
// fs.pickle from the now-live honeyfs) on boot. Giving this service its
// own Docker access would just be a second, redundant path to the same
// privilege autoheal already owns.
package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// maxImplantBytes bounds a single implanted artifact -- generous for a
// planted document/script, far below anything that would strain the host.
const maxImplantBytes = 8 << 20 // 8MB

// maxImplantPathBytes bounds implantRequest.Path for the sole purpose of
// sizing maxImplantWireBytes below -- it is not itself an enforced limit on
// req.Path (resolveHoneyfsPath's containment check is what actually
// validates the path). 4096 matches Linux's own PATH_MAX; no real honeyfs
// path from the dashboard is remotely close to it, so this is pure margin.
const maxImplantPathBytes = 4096

// maxImplantWireBytes bounds the raw HTTP request body http.MaxBytesReader
// accepts, in encoded-JSON bytes -- not maxImplantBytes, which bounds the
// *decoded* content (#2338). Base64 standard encoding of n bytes produces
// exactly 4*ceil(n/3) characters, so an 8MiB implant's content_base64 value
// alone is already ~11.18MB before any JSON syntax is added; capping the
// reader at maxImplantBytes+64KiB (the previous shape) meant every implant
// whose raw size exceeded roughly maxImplantBytes*3/4 (~6.15MiB) died
// inside json.Decode with a generic "invalid request" 400 instead of ever
// reaching the len(content) > maxImplantBytes check below -- silently
// cutting off the top ~30% of the documented 0-8MiB implant range, and
// making that check dead code for every request that actually needed it.
//
// The formula below is derived, not padded by feel: exact base64 ceiling
// for the largest content this handler will ever accept, plus
// maxImplantPathBytes of headroom for req.Path, plus 256 bytes for the
// struct's own JSON punctuation (field names, quotes, braces, the comma,
// and base64's own up-to-2 bytes of "=" padding) -- enough that a
// maximally-sized, validly-encoded request can never be rejected by the
// reader cap, while a request that pads content_base64 with garbage past
// what a real base64 encoding of maxImplantBytes could ever produce still
// hits this cap instead of being handed to json.Decode unbounded.
const maxImplantWireBytes = ((maxImplantBytes + 2) / 3 * 4) + maxImplantPathBytes + 256

type server struct {
	honeyfsDir string
	markerPath string

	// Concurrent implants writing overlapping directory trees could race
	// MkdirAll/WriteFile against each other; one write at a time is plenty
	// for an operator-driven action, not a hot path.
	mu sync.Mutex
}

type implantRequest struct {
	// Path is relative to the honeyfs root, e.g. "home/mwagner/.aws/credentials".
	Path string `json:"path"`
	// ContentBase64 is the raw artifact bytes, base64-encoded so this
	// endpoint works uniformly for text (a credential file) and binary
	// (a downloaded canarytoken document) content.
	ContentBase64 string `json:"content_base64"`
	// Memo is operator-supplied context, logged for audit only -- this
	// service has no store of its own. Bookkeeping (which token/credential
	// this corresponds to) is the dashboard's own job (#1487 item 5).
	Memo string `json:"memo"`
}

type implantResponse struct {
	OK           bool   `json:"ok"`
	Path         string `json:"path,omitempty"`
	BytesWritten int    `json:"bytes_written,omitempty"`
	Error        string `json:"error,omitempty"`
}

// resolveHoneyfsPath rejects anything that would escape honeyfsDir --
// absolute paths, ".." traversal, or a clean-but-still-outside result.
// Mirrors the containment-check shape this repo already uses elsewhere for
// user-influenced paths (see codeql-config.yml's server.py comment).
func (s *server) resolveHoneyfsPath(reqPath string) (string, error) {
	if reqPath == "" {
		return "", errors.New("path is required")
	}
	if filepath.IsAbs(reqPath) {
		return "", errors.New("path must be relative to the honeyfs root")
	}
	cleaned := filepath.Clean(reqPath)
	if cleaned == "." || strings.HasPrefix(cleaned, "..") {
		return "", errors.New("path escapes the honeyfs root")
	}
	root, err := filepath.Abs(s.honeyfsDir)
	if err != nil {
		return "", err
	}
	full := filepath.Join(root, cleaned)
	if full != root && !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return "", errors.New("path escapes the honeyfs root")
	}
	return full, nil
}

func (s *server) handleImplant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req implantRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxImplantWireBytes)).Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			// Distinct message from both the generic "invalid request"
			// below and the post-decode "content exceeds 8MB implant
			// limit" further down -- this is the wire-size limit
			// (base64-encoded content plus JSON envelope), tripped before
			// the request body is even valid JSON yet.
			writeError(w, http.StatusBadRequest, "request body exceeds the base64-encoded implant size limit")
			return
		}
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}
	target, err := s.resolveHoneyfsPath(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	content, err := base64.StdEncoding.DecodeString(req.ContentBase64)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid content_base64: %v", err))
		return
	}
	if len(content) == 0 {
		writeError(w, http.StatusBadRequest, "content_base64 decodes to zero bytes")
		return
	}
	if len(content) > maxImplantBytes {
		writeError(w, http.StatusBadRequest, "content exceeds 8MB implant limit")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("mkdir: %v", err))
		return
	}
	if err := os.WriteFile(target, content, 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("write: %v", err))
		return
	}

	// %q, not %s, for req.Path -- it's operator-controlled but unvalidated
	// for log-safety specifically (resolveHoneyfsPath only checks it can't
	// escape honeyfsDir), so a newline in it could otherwise forge fake
	// log lines. Matches canarytokens-adapter's own fix for the same class
	// of finding (#1487, #1556).
	log.Printf("implanted %d bytes at %q (memo=%q)", len(content), req.Path, req.Memo)

	if err := s.setImplantPending(); err != nil {
		// The file is planted; a missed marker just means the operator has
		// to wait for cowrie's own next scheduled restart instead of an
		// immediate autoheal-triggered one. Not worth failing over.
		log.Printf("warning: failed to set implant-pending marker: %v", err)
	}

	writeJSON(w, http.StatusOK, implantResponse{OK: true, Path: req.Path, BytesWritten: len(content)})
}

// setImplantPending drops the marker cowrie's own HEALTHCHECK (compose.yml)
// checks for -- see this file's package doc for the full restart chain.
func (s *server) setImplantPending() error {
	if err := os.MkdirAll(filepath.Dir(s.markerPath), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(s.markerPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "implanted at %s\n", time.Now().UTC().Format(time.RFC3339))
	return err
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, implantResponse{OK: false, Error: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat(s.honeyfsDir); err != nil {
		http.Error(w, "honeyfs mount not reachable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// requireToken is a defense-in-depth constant-time bearer check, layered
// under the primary WireGuard-tunnel-only boundary -- optional (empty
// IMPLANT_TOKEN disables it) since every other internal-only API in this
// repo relies on network reachability alone and this matches that
// convention by default, but implant is a write path onto a live
// honeypot's own fake filesystem, so an operator can opt into a shared
// secret if they want a second layer.
func requireToken(token string, next http.HandlerFunc) http.HandlerFunc {
	if token == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// listenAddr and healthzURL share the same LISTEN_ADDR-derived port so
// -healthcheck (below, matching canarytokens-adapter/Dockerfile's own
// scratch-image HEALTHCHECK convention -- no curl/wget in this minimal
// image either) always checks the port this same binary is actually
// listening on.
func healthzURL(addr string) string {
	host := addr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	return "http://" + host + "/healthz"
}

// loadToken resolves the bearer token from IMPLANT_TOKEN or from the file
// IMPLANT_TOKEN_FILE names, mirroring the backend's trust::secret (the
// client side, #3680). An empty IMPLANT_TOKEN counts as unset (the
// documented default: neither set means the token check stays off); a set
// one is used verbatim, as the client sends it. A file is read once, with
// surrounding whitespace (echo's trailing newline) trimmed. Setting both, or naming an unreadable or empty file, is an
// error: main refuses to start rather than serve without the auth the
// operator configured.
func loadToken(env func(string) string, read func(string) ([]byte, error)) (string, error) {
	direct := env("IMPLANT_TOKEN")
	path := strings.TrimSpace(env("IMPLANT_TOKEN_FILE"))
	switch {
	case direct != "" && path != "":
		return "", errors.New("both IMPLANT_TOKEN and IMPLANT_TOKEN_FILE are set; set one")
	case direct != "":
		return direct, nil
	case path != "":
		b, err := read(path)
		if err != nil {
			return "", fmt.Errorf("IMPLANT_TOKEN_FILE names %q, which cannot be read: %v", path, err)
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return "", errors.New("IMPLANT_TOKEN_FILE names an empty file")
		}
		return v, nil
	}
	return "", nil
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "check this instance's own /healthz and exit 0/1, for HEALTHCHECK CMD")
	flag.Parse()

	addr := getenv("LISTEN_ADDR", ":8091")

	if *healthcheck {
		resp, err := http.Get(healthzURL(addr))
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	s := &server{
		honeyfsDir: getenv("HONEYFS_DIR", "/data/honeyfs"),
		markerPath: getenv("MARKER_PATH", "/data/lib/.implant-pending"),
	}
	token, err := loadToken(os.Getenv, os.ReadFile)
	if err != nil {
		log.Fatalf("[E-IMPLANT-TOKEN] refusing to start: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/implant", requireToken(token, s.handleImplant))
	mux.HandleFunc("/healthz", s.handleHealthz)

	log.Printf("honeyfs-implant listening on %s (honeyfs=%s)", addr, s.honeyfsDir)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

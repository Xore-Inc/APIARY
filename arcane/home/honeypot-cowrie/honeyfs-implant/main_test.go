package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveHoneyfsPathRejectsEscapes throws a battery of path-traversal
// shapes at resolveHoneyfsPath -- CodeQL's go/path-injection query flagged
// the sink this function guards (main.go's MkdirAll/WriteFile calls) since
// it doesn't model a custom containment check as a sanitizer. This proves
// the containment actually holds rather than asserting it by inspection.
func TestResolveHoneyfsPathRejectsEscapes(t *testing.T) {
	s := &server{honeyfsDir: t.TempDir()}
	root, err := filepath.Abs(s.honeyfsDir)
	if err != nil {
		t.Fatal(err)
	}

	malicious := []string{
		"../etc/passwd",
		"../../etc/passwd",
		"../../../../../../etc/passwd",
		"..",
		"foo/../../etc/passwd",
		"foo/../../../etc/passwd",
		"a/b/../../../../etc/passwd",
		"/etc/passwd",
		"/etc/../etc/passwd",
		"",
		".",
		"./..",
		"foo/./../../bar",
		"....//....//etc/passwd", // not a real ".." shape, but exercise it anyway
	}
	for _, raw := range malicious {
		t.Run(raw, func(t *testing.T) {
			resolved, err := s.resolveHoneyfsPath(raw)
			if err == nil {
				t.Fatalf("path %q was accepted, resolved to %q -- should have been rejected", raw, resolved)
			}
		})
	}

	// Sanity check the positive case isn't accidentally broken too.
	for _, raw := range []string{"home/mwagner/.aws/credentials", "a/b/c.txt", "file.txt"} {
		t.Run("valid/"+raw, func(t *testing.T) {
			resolved, err := s.resolveHoneyfsPath(raw)
			if err != nil {
				t.Fatalf("legitimate path %q was rejected: %v", raw, err)
			}
			if !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
				t.Fatalf("resolved path %q escaped root %q", resolved, root)
			}
		})
	}
}

// TestHandleImplantSizeBoundary covers #2338: the wire-size reader cap
// must not reject implants the post-decode maxImplantBytes check would
// otherwise accept. Base64 inflates 4/3, so a raw implant just under the
// old maxImplantBytes+64KiB reader cap was already impossible above
// roughly maxImplantBytes*3/4 (~6.15MiB) -- this is the case the fix
// exists for, and it can only be proven by exercising the real handler
// with real request bodies at each size, not by reading the arithmetic.
func TestHandleImplantSizeBoundary(t *testing.T) {
	s := &server{honeyfsDir: t.TempDir(), markerPath: filepath.Join(t.TempDir(), "implant-pending")}
	srv := httptest.NewServer(http.HandlerFunc(s.handleImplant))
	defer srv.Close()

	post := func(t *testing.T, rawSize int) (*http.Response, string) {
		t.Helper()
		content := bytes.Repeat([]byte{0x41}, rawSize)
		body, err := json.Marshal(implantRequest{
			Path:          fmt.Sprintf("boundary-test-%d.bin", rawSize),
			ContentBase64: base64.StdEncoding.EncodeToString(content),
		})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp, string(respBody)
	}

	t.Run("comfortably_under_limit_succeeds", func(t *testing.T) {
		resp, body := post(t, 1<<20) // 1MiB raw
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %s", resp.StatusCode, body)
		}
	})

	t.Run("between_wire_cap_and_content_cap_now_succeeds", func(t *testing.T) {
		// 7MiB raw content, base64-encoded, is ~9.34MB on the wire -- well
		// past the OLD reader cap (maxImplantBytes+64KiB = ~8.06MB) but well
		// under maxImplantBytes (8MiB) once decoded. This is the exact
		// range the issue reports as unreachable.
		resp, body := post(t, 7<<20)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (this raw size must be reachable); body = %s", resp.StatusCode, body)
		}
	})

	t.Run("genuinely_over_limit_hits_the_intended_message", func(t *testing.T) {
		// maxImplantBytes+2048 raw content decodes to just over the
		// content-size limit while its base64 form (~2.7KB larger encoded
		// than a maximally-sized valid implant) is still comfortably
		// inside maxImplantWireBytes' path/JSON margin -- this must reach
		// and trip the len(content) > maxImplantBytes check, proving that
		// branch is no longer dead code the way a much larger raw size
		// (whose *encoded* form also exceeds the wire cap, covered by the
		// next subtest) would be.
		resp, body := post(t, maxImplantBytes+2048)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body = %s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "content exceeds 8MB implant limit") {
			t.Fatalf("body = %s, want the post-decode over-limit message, not a wire-cap or generic-decode message", body)
		}
	})

	t.Run("wire_cap_still_rejects_something_no_valid_request_could_ever_be", func(t *testing.T) {
		// A body larger than maxImplantWireBytes can't decode to a valid
		// implant at any size. Wrapped in valid JSON string syntax (not
		// just raw garbage) so json.Decode actually has to keep pulling
		// bytes into the content_base64 string token instead of failing
		// on the first byte -- that's what makes MaxBytesReader's own
		// overflow check the thing that trips, rather than a syntax
		// error firing first and never exercising the reader cap at all.
		body := []byte(`{"path":"x","content_base64":"` + strings.Repeat("A", maxImplantWireBytes+1024) + `"}`)
		resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body = %s", resp.StatusCode, respBody)
		}
		if !strings.Contains(string(respBody), "exceeds the base64-encoded implant size limit") {
			t.Fatalf("body = %s, want the wire-cap message", respBody)
		}
	})
}

func TestLoadToken(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good", "s3cret\n")
	empty := write("empty", " \n\t\n")
	cases := []struct {
		name    string
		env     map[string]string
		want    string
		wantErr string
	}{
		{"neither set", nil, "", ""},
		{"empty env counts as unset", map[string]string{"IMPLANT_TOKEN": ""}, "", ""},
		{"env used verbatim, like the client", map[string]string{"IMPLANT_TOKEN": " abc "}, " abc ", ""},
		{"env only", map[string]string{"IMPLANT_TOKEN": "abc"}, "abc", ""},
		{"file only, trailing newline", map[string]string{"IMPLANT_TOKEN_FILE": good}, "s3cret", ""},
		{"both set", map[string]string{"IMPLANT_TOKEN": "abc", "IMPLANT_TOKEN_FILE": good}, "", "both IMPLANT_TOKEN and IMPLANT_TOKEN_FILE are set"},
		{"missing file", map[string]string{"IMPLANT_TOKEN_FILE": filepath.Join(dir, "nope")}, "", "which cannot be read"},
		{"empty file", map[string]string{"IMPLANT_TOKEN_FILE": empty}, "", "names an empty file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := loadToken(func(k string) string { return c.env[k] }, os.ReadFile)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, c.wantErr)
				}
				if got != "" {
					t.Fatalf("token %q returned alongside error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

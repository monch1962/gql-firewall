package integration

import (
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Not in CAPEC: toolchain/dependency downgrade that silently reintroduces
// fixed standard-library denial-of-service vectors (GO-2026-6603 … GO-2026-6617).
//
// The sidecar terminates HTTP/1.1 and HTTP/2 and proxies to the upstream, so a
// stdlib net/http regression is a first-class attack surface for this project:
// the go1.25 line is out of support and carries 10 reachable advisories
// (HPACK encoder race crash, HTTP/2 trailer memory exhaustion, MIME header
// memory-limit bypass, CONNECT desynchronization, and related flow-control
// abuse). Pinning the build back to a vulnerable toolchain would silently
// reopen all of them, so the floor is asserted in CI rather than left to
// code review.
func TestBuild_ToolchainAtLeastNetHTTPSecurityFloor(t *testing.T) {
	// Lowest release that fixes every stdlib advisory govulncheck reported
	// against the previously pinned go1.25.13: go1.26.10 (x509, GO-2026-6809).
	const (
		floorMajor = 1
		floorMinor = 26
		floorPatch = 10
	)

	got := runtime.Version()
	major, minor, patch, ok := parseGoVersion(got)
	if !ok {
		t.Fatalf("cannot parse toolchain version %q", got)
	}
	if major != floorMajor {
		if major < floorMajor {
			t.Fatalf("toolchain %q predates the security floor go%d.%d.%d", got, floorMajor, floorMinor, floorPatch)
		}
		return // newer major line is acceptable
	}
	if minor < floorMinor || (minor == floorMinor && patch < floorPatch) {
		t.Fatalf("toolchain %q is below the security floor go%d.%d.%d: "+
			"stdlib advisories GO-2026-6603..6809 (net/http DoS, x509 trust) are reachable",
			got, floorMajor, floorMinor, floorPatch)
	}
}

// TestBuild_GoModToolchainPinnedToSecurityFloor guards the other half of the
// contract: the local runtime can be modern while go.mod still pins a
// vulnerable toolchain, which would downgrade CI and container builds.
func TestBuild_GoModToolchainPinnedToSecurityFloor(t *testing.T) {
	const floor = "go1.26.10"

	raw, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	m := regexp.MustCompile(`(?m)^toolchain\s+(\S+)\s*$`).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatalf("go.mod has no toolchain directive; the vulnerable-toolchain floor is unenforced")
	}
	pinned := m[1]
	pm, pn, pp, ok := parseGoVersion(pinned)
	fm, fn, fp, okFloor := parseGoVersion(floor)
	if !ok || !okFloor {
		t.Fatalf("cannot parse toolchain directive %q", pinned)
	}
	if pm < fm || (pm == fm && (pn < fn || (pn == fn && pp < fp))) {
		t.Fatalf("go.mod pins toolchain %q, below security floor %q", pinned, floor)
	}
}

func parseGoVersion(v string) (major, minor, patch int, ok bool) {
	v = strings.TrimPrefix(v, "go")
	if i := strings.IndexFunc(v, func(r rune) bool {
		return !(r >= '0' && r <= '9') && r != '.'
	}); i >= 0 { // drop suffixes like "rc1", "X:y" (gccgo)
		v = v[:i]
	}
	parts := strings.Split(strings.Trim(v, "."), ".")
	if len(parts) < 2 {
		return 0, 0, 0, false
	}
	nums := make([]int, 3)
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return 0, 0, 0, false
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], true
}

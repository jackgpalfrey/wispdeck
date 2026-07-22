package buildinfo

import "testing"

func TestCurrentUsesSafeDevelopmentFallbacks(t *testing.T) {
	originalVersion, originalCommit, originalBuiltAt := version, commit, builtAt
	t.Cleanup(func() { version, commit, builtAt = originalVersion, originalCommit, originalBuiltAt })
	version, commit, builtAt = " ", "", "\t"

	info := Current()
	if info.Version != "dev" || info.Commit != "unknown" || info.BuiltAt != "unknown" || info.GoVersion == "" {
		t.Fatalf("build info = %+v", info)
	}
}

func TestCurrentTrimsInjectedMetadata(t *testing.T) {
	originalVersion, originalCommit, originalBuiltAt := version, commit, builtAt
	t.Cleanup(func() { version, commit, builtAt = originalVersion, originalCommit, originalBuiltAt })
	version, commit, builtAt = " v1.2.3 ", " abc123 ", " 2026-07-22T12:00:00Z "

	info := Current()
	if info.Version != "v1.2.3" || info.Commit != "abc123" || info.BuiltAt != "2026-07-22T12:00:00Z" {
		t.Fatalf("build info = %+v", info)
	}
}

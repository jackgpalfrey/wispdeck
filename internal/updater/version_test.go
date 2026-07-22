package updater

import "testing"

func TestStableVersionParsingAndComparison(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"v0.0.0", "v1.2.3", "v18446744073709551615.0.9"} {
		version, err := ParseVersion(value)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", value, err)
		}
		if version.String() != value {
			t.Fatalf("ParseVersion(%q).String() = %q", value, version.String())
		}
	}
	for _, value := range []string{"", "1.2.3", "v1", "v1.2", "v1.2.3.4", "v01.2.3", "v1.02.3", "v1.2.03", "v1.2.3-rc1", "v1.2.3+meta", "v-1.2.3"} {
		if _, err := ParseVersion(value); err == nil {
			t.Fatalf("ParseVersion(%q) succeeded", value)
		}
	}
	v1, _ := ParseVersion("v1.9.9")
	v2, _ := ParseVersion("v2.0.0")
	if v1.Compare(v2) >= 0 || v2.Compare(v1) <= 0 || v1.Compare(v1) != 0 {
		t.Fatal("version comparison is incorrect")
	}
}

package auth

import "testing"

func TestInitialSetupCodeFormat(t *testing.T) {
	t.Parallel()
	for range 100 {
		code, err := NewInitialSetupCode()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidInitialSetupCode(code) || len(code) != InitialSetupCodeLength {
			t.Fatalf("invalid generated setup code %q", code)
		}
	}
	if NormalizeInitialSetupCode(" abcd23 ") != "ABCD23" || !ValidInitialSetupCode(" abcd23 ") {
		t.Fatal("setup code normalization failed")
	}
	for _, invalid := range []string{"", "ABCDE", "ABCDEFG", "ABCD10", "ABC-23"} {
		if ValidInitialSetupCode(invalid) {
			t.Fatalf("accepted invalid setup code %q", invalid)
		}
	}
}

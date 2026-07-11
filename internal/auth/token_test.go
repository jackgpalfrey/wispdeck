package auth

import "testing"

func TestTokensAreValidAndUnique(t *testing.T) {
	first, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidToken(first) || !ValidToken(second) {
		t.Fatal("generated token failed validation")
	}
	if first == second {
		t.Fatal("generated duplicate tokens")
	}
	if ValidToken("short") {
		t.Fatal("accepted malformed token")
	}
}

package auth

import (
	"bytes"
	"testing"
)

func TestPasswordManagerPepperAndLegacyUpgrade(t *testing.T) {
	useFastPasswordParams(t)
	firstKeys, err := NewKeyMaterial(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secondKeys, err := NewKeyMaterial(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := NewPasswordManager(firstKeys)
	second, _ := NewPasswordManager(secondKeys)
	password := "saffron-planetary-cello-woodland"
	hash, err := first.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if matched, err := first.Verify(password, hash); err != nil || !matched {
		t.Fatalf("peppered verification = (%v, %v)", matched, err)
	}
	if matched, err := second.Verify(password, hash); err != nil || matched {
		t.Fatalf("wrong-pepper verification = (%v, %v)", matched, err)
	}
	if first.NeedsUpgrade(hash) {
		t.Fatal("new peppered hash unexpectedly needs upgrade")
	}

	legacy, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if matched, err := first.Verify(password, legacy); err != nil || !matched {
		t.Fatalf("legacy verification = (%v, %v)", matched, err)
	}
	if !first.NeedsUpgrade(legacy) {
		t.Fatal("legacy hash was not marked for upgrade")
	}
}

package main

import (
	"testing"

	shadowarmor "github.com/Shadow-Security-official/Shadow-Armor"
)

// Same value as Python's uuid.uuid5(uuid.NAMESPACE_URL, name).
func TestUUID5(t *testing.T) {
	got := uuid5("https://github.com/Shadow-Security-official/Shadow-Armor@v0.1.0")
	if want := "7d287576-1a9f-5764-bf2d-53d411bcdccf"; got != want {
		t.Fatalf("uuid5 = %s, want %s", got, want)
	}
}

func TestTreeHashIsStable(t *testing.T) {
	a, n, err := treeHash(shadowarmor.Profile, "profile")
	if err != nil || n < 10 || len(a) != 64 {
		t.Fatalf("hash %q over %d files: %v", a, n, err)
	}
	b, _, _ := treeHash(shadowarmor.Profile, "profile")
	c, _, _ := treeHash(shadowarmor.Cookbook, "cookbook")
	if a != b || a == c {
		t.Fatal("the tree hash must be deterministic and differ between trees")
	}
}

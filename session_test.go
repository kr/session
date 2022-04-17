package session

import (
	"testing"

	"filippo.io/age"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Keys: []*age.X25519Identity{key},
	}

	type T struct {
		V string
	}

	token, err := Encode(T{V: "foobar"}, cfg)
	if err != nil {
		t.Fatal(err)
	}

	var got T
	if err := Decode(token, &got, cfg); err != nil {
		t.Fatal(err)
	}

	want := T{V: "foobar"}
	if got.V != want.V {
		t.Errorf("got %q, want %q", got.V, want.V)
	}
}

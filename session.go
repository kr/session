package session

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	maxSize = 4093
)

type Config struct {
	// The cookie name.
	// If empty, "session" is used.
	Name string

	// The cookie path.
	// If empty, "/" is used.
	Path string

	// The cookie domain.
	// If empty, the request host is used.
	Domain string

	// Maximum idle time for a session.
	// This is used to set cookie expiration and
	// enforce a TTL on secret boxes.
	// If 0, it is taken to be 100 years.
	MaxAge time.Duration

	// List of acceptable secretbox keys for decoding stored sessions.
	// Element 0 will be used for encoding.
	// See golang.org/x/crypto/nacl/secretbox.
	Keys []*[32]byte
}

func (c *Config) maxAge() time.Duration {
	if c.MaxAge == 0 {
		return 100 * 365 * 24 * time.Hour
	}
	return c.MaxAge
}

func (c *Config) name() string {
	if c.Name == "" {
		return "session"
	}
	return c.Name
}

// Indicates the encoded session cookie is too long
// to expect web browsers to store it.
var (
	ErrTooLong = errors.New("encoded session too long")
	ErrInvalid = errors.New("invalid session cookie")
)

// Get decodes a session from r into v.
// See encoding/json for decoding behavior.
func Get(r *http.Request, v interface{}, config *Config) error {
	cookie, err := r.Cookie(config.name())
	if err != nil {
		return err
	}
	t := []byte(cookie.Value)
	var nonce [24]byte
	copy(nonce[:], t)
	for _, key := range config.Keys {
		if tb, ok := secretbox.Open(nil, t[24:], &nonce, key); ok {
			ts := binary.BigEndian.Uint64(tb)
			if time.Since(time.Unix(int64(ts), 0)) > config.maxAge() {
				return ErrInvalid
			}
			b := tb[8:]
			return json.Unmarshal(b, v)
		}
	}
	return ErrInvalid
}

// Set encodes a session from v into a cookie on w.
// See encoding/json for encoding behavior.
func Set(w http.ResponseWriter, v interface{}, config *Config) error {
	now := time.Now()
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tb := make([]byte, len(b)+8)
	binary.BigEndian.PutUint64(tb, uint64(now.Unix()))
	copy(tb[8:], b)
	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	if err != nil {
		return err
	}
	out := secretbox.Seal(nonce[:], tb, &nonce, config.Keys[0])
	cookie := &http.Cookie{
		Name:     config.name(),
		Value:    string(out),
		Expires:  now.Add(config.maxAge()),
		Path:     config.Path,
		Domain:   config.Domain,
		Secure:   true,
		HttpOnly: true,
	}
	if cookie.Path == "" {
		cookie.Path = "/"
	}
	s := cookie.String()
	if len(s) > maxSize {
		return ErrTooLong
	}
	w.Header().Add("Set-Cookie", s)
	return nil
}

package session

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"filippo.io/age"
)

const (
	maxSize = 4093
)

var (
	encBig = binary.BigEndian
	encURL = base64.URLEncoding
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

	// Whether the cookie should be limited to HTTPS.
	Secure bool

	// Whether the cookie will not be available to JavaScript.
	HTTPOnly bool

	// Maximum idle time for a session.
	// This is used to set cookie expiration and
	// enforce a TTL on secret boxes.
	// If 0, it is taken to be 100 years.
	MaxAge time.Duration

	// Keys is used to encrypt and decrypt sessions.
	//
	// Sessions are encrypted to all keys to facilitate
	// seamless key rotation. As long as there is an overlap
	// between the sets of keys on two servers, sessions can
	// be encrypted and decrypted on either server.
	//
	// Overhead (after base64) is about 266 bytes per key.
	//
	// See filippo.io/age.
	Keys []*age.X25519Identity
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

var (
	// ErrTooLong indicates that an encoded session cookie is too long
	// to expect web browsers to store it.
	ErrTooLong = errors.New("encoded session too long")

	// ErrInvalid indicates that a session cookie could not be decoded,
	// either because its expiration time is in the past or because none
	// of the provided keys could decrypt it.
	ErrInvalid = errors.New("invalid session cookie")
)

// Get decodes a session from req into v.
// See encoding/json for decoding behavior.
func Get(req *http.Request, v interface{}, config *Config) error {
	cookie, err := req.Cookie(config.name())
	if err != nil {
		return err
	}
	var ident []age.Identity
	for _, key := range config.Keys {
		ident = append(ident, key)
	}
	r, err := age.Decrypt(base64.NewDecoder(encURL, strings.NewReader(cookie.Value)), ident...)
	if err != nil {
		return err
	}
	var ts int64
	err = binary.Read(r, encBig, &ts)
	if err != nil {
		return err
	}
	if time.Since(time.Unix(ts, 0)) > config.maxAge() {
		return errors.New("expired cookie")
	}
	return json.NewDecoder(r).Decode(v)
}

// Set encodes a session from v into a cookie on w.
// See encoding/json for encoding behavior.
func Set(w http.ResponseWriter, v interface{}, config *Config) error {
	now := time.Now()
	var recip []age.Recipient
	for _, key := range config.Keys {
		recip = append(recip, key.Recipient())
	}
	out := &strings.Builder{}
	enc, err := age.Encrypt(base64.NewEncoder(encURL, out), recip...)
	if err != nil {
		return err
	}
	_ = binary.Write(enc, encBig, now.Unix())
	_ = json.NewEncoder(enc).Encode(v)
	err = enc.Close()
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name:     config.name(),
		Value:    out.String(),
		Expires:  now.Add(config.maxAge()),
		Path:     config.Path,
		Domain:   config.Domain,
		Secure:   config.Secure,
		HttpOnly: config.HTTPOnly,
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

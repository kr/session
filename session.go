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

// defaultCookie is the real value that never changes.
var defaultCookie = DefaultCookie

// DefaultCookie documents the Cookie settings used by functions
// in this package when Config.Cookie is nil.
//
// Changes to DefaultCookie will not affect the behavior of
// this package. It is only for documentation.
var DefaultCookie = http.Cookie{
	Name:     "session",
	Path:     "/",
	MaxAge:   100 * 365 * 24 * 60 * 60,
	Secure:   true,
	HttpOnly: true,
	SameSite: http.SameSiteLaxMode,
}

type Config struct {
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

	// Cookie controls encoding and decoding cookies, as in package
	// http. This package sets Value and uses all other fields as-is.
	//
	// If nil, DefaultCookie is used.
	Cookie *http.Cookie
}

func (c *Config) cookie() http.Cookie {
	if c.Cookie == nil {
		return defaultCookie
	}
	return *c.Cookie
}

// Errors
var (
	// ErrTooLong indicates that an encoded session cookie is too long
	// to expect web browsers to store it.
	ErrTooLong = errors.New("encoded session too long")

	// ErrInvalid indicates that a session cookie or authentication token
	// could not be decoded, either because its expiration time is in the
	// past or because none of the provided keys could decrypt it.
	ErrInvalid = errors.New("invalid session cookie or token")
)

// Get decodes a session from req into v.
// See encoding/json for decoding behavior.
func Get(req *http.Request, v interface{}, config *Config) error {
	cookie, err := req.Cookie(config.cookie().Name)
	if err != nil {
		return err
	}
	return Decode(cookie.Value, v, config)
}

// Set encodes a session from v into a cookie on w.
// See encoding/json for encoding behavior.
func Set(w http.ResponseWriter, v interface{}, config *Config) error {
	token, err := Encode(v, config)
	if err != nil {
		return err
	}
	cookie := config.cookie()
	cookie.Value = token
	s := cookie.String()
	if len(s) > maxSize {
		return ErrTooLong
	}
	w.Header().Add("Set-Cookie", s)
	return nil
}

// Decode decodes the encrypted token into v.
// See encoding/json for decoding behavior.
func Decode(token string, v interface{}, config *Config) error {
	var ident []age.Identity
	for _, key := range config.Keys {
		ident = append(ident, key)
	}
	r, err := age.Decrypt(base64.NewDecoder(encURL, strings.NewReader(token)), ident...)
	if err != nil {
		return err
	}
	var expires int64
	err = binary.Read(r, encBig, &expires)
	if err != nil {
		return err
	}
	if time.Since(time.Unix(expires, 0)) > 0 {
		return ErrInvalid
	}
	return json.NewDecoder(r).Decode(v)
}

// Encode encodes a token set to expire after config.Cookie.MaxAge. This
// is intended to be used with Decode. If using sessions, you probably
// want to use Set. See encoding/json for encoding behavior.
func Encode(v interface{}, config *Config) (string, error) {
	expires := time.Now().Unix() + int64(config.cookie().MaxAge)
	var recip []age.Recipient
	for _, key := range config.Keys {
		recip = append(recip, key.Recipient())
	}
	out := &strings.Builder{}
	enc, err := age.Encrypt(base64.NewEncoder(encURL, out), recip...)
	if err != nil {
		return "", err
	}
	_ = binary.Write(enc, encBig, expires)
	_ = json.NewEncoder(enc).Encode(v)
	err = enc.Close()
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

// Package session provides a convenient way to store session data
// (such as a user ID) securely in a web browser cookie or other
// authentication token. Cookie values generated by this package
// use modern authenticated encryption, so they can't be inspected
// or altered by client processes.
//
// Most users of this package will use functions Set and Get, which
// manage cookies directly. An analogous pair of functions, Encode and
// Decode, help when the session data will be stored somewhere other
// than a browser cookie; for example, an API token configured by hand
// in an API client process.
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

	// Cookie controls encoding and decoding cookies, as in
	// net/http, except that Cookie.Value is ignored.
	// (The cookie value is provided by Set.)
	//
	// If Cookie is nil, DefaultCookie is used.
	Cookie *http.Cookie
}

func (c *Config) cookie() http.Cookie {
	if c.Cookie == nil {
		return defaultCookie
	}
	return *c.Cookie
}

// Get decodes a session from req into v.
// See encoding/json for decoding behavior.
//
// Non-nil error values indicate that
// no valid session was present in req.
// Typically, the specific error information is useful
// only for debugging.
// In an ordinary production setting,
// any non-nil error should be treated simply
// as an unauthenticated request
// (e.g. a fresh visitor who hasn't logged in yet).
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
	return setCookie(w.Header(), &cookie)
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
		return errors.New("expired")
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
	be := base64.NewEncoder(encURL, out)
	enc, err := age.Encrypt(be, recip...)
	if err != nil {
		return "", err
	}
	_ = binary.Write(enc, encBig, expires)
	_ = json.NewEncoder(enc).Encode(v)
	err = enc.Close()
	if err != nil {
		return "", err
	}
	err = be.Close()
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

// setCookie sets the given cookie in h.
// If any existing Set-Cookie values have the same cookie name,
// it replaces each one,
// otherwise it adds a new one.
func setCookie(h http.Header, cookie *http.Cookie) error {
	s := cookie.String()
	if s == "" {
		return errors.New("invalid")
	}
	didReplace := false
	a := h["Set-Cookie"]
	for i := range a {
		if isValidCookie(a[i], cookie.Name) {
			a[i] = s
			didReplace = true
		}
	}
	if !didReplace {
		h.Add("Set-Cookie", s)
	}
	return nil
}

// isValidCookie returns whether s is a valid Set-Cookie encoding
// of a cookie with the given name.
func isValidCookie(s, name string) bool {
	resp := &http.Response{Header: http.Header{"Set-Cookie": []string{s}}}
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return true
		}
	}
	return false
}

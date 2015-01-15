package session

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/fernet/fernet-go"
)

const (
	maxSize = 4093
)

type Config struct {
	// Cookie initializes the cookie to encode each
	// session. If Name, Path, and Domain are empty,
	// "session", "/" and the request host are used,
	// respectively.
	http.Cookie

	// Maximum idle time for a session.
	// This is used to set cookie expiration and
	// enforce TTL on fernet tokens.
	// If 0, it is taken to be 100 years.
	MaxAge time.Duration

	// List of acceptable keys for decoding stored sessions.
	// Element 0 will be used for encoding.
	Keys []*fernet.Key
}

func (c *Config) maxAge() time.Duration {
	if c.MaxAge == 0 {
		return 100 * 365 * 24 * time.Hour
	}
	return c.MaxAge
}

func (c *Config) name() string {
	if c.Cookie.Name == "" {
		return "session"
	}
	return c.Cookie.Name
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
	b := fernet.VerifyAndDecrypt(t, config.maxAge(), config.Keys)
	if b == nil {
		return ErrInvalid
	}
	return json.Unmarshal(b, v)
}

// Set encodes a session from v into a cookie on w.
// See encoding/json for encoding behavior.
func Set(w http.ResponseWriter, v interface{}, config *Config) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	t, err := fernet.EncryptAndSign(b, config.Keys[0])
	if err != nil {
		return err
	}
	cookie := config.Cookie
	cookie.Name = config.name()
	cookie.Value = string(t)
	cookie.Expires = time.Now().Add(config.maxAge())
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

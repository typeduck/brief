// package brief generates unforgeable tokens of cryptographically signed data
// with a build-in expiration. It is lighter than JWT, but more limited.
//
// Inspired by: https://pdos.csail.mit.edu/papers/webauth:sec10.pdf
//
// If you need something more fully-featured than arbitrary data signed and
// verified with an expiration date, you should look into JWT.
//
//	mint := brief.NewMint([]byte("your secret hmac key"))
//	...
//	token, err := mint.Sign([]byte("your tamper proof data"), time.Now().Add(time.Hour))
//	cookieValue := token.String() // serialize
//	...
//	token, err := mint.VerifyString(cookieValue)
package brief

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	timeLayout = "20060102150405"
	sep        = "."
)

var (
	// ErrFormat indicates that the serialized Token was malformed.
	ErrFormat = errors.New("format invalid")

	// ErrParse indicates an error in parsing a string token.
	ErrParse = errors.New("parsing")

	// ErrFieldData indicates that there was an error with the Data field.
	ErrFieldData = errors.New("data")

	// ErrFieldSignature indicates there was an error with the Signature field.
	ErrFieldSignature = errors.New("signature")

	// ErrFieldExpiry indicates there was an error with the Expiry field parsing.
	ErrFieldExpiry = errors.New("expiry")

	// ErrDecoding indicates that badly encoding data was given to parse.
	ErrDecoding = errors.New("decoding")

	// ErrVerifySignature indicates the signature did not match the data.
	ErrVerifySignature = errors.New("invalid signature")

	// ErrVerifyExpiry indicates that the Token has expired.
	ErrVerifyExpiry = errors.New("expired")
)

// For all encoding/decoding base64, use RawURLEncoding to avoid padding
var encoding = base64.RawURLEncoding

// Encode encodes arbitrary data same as the individual parts in Token.String().
// It could be useful to use Encode(Token.Data).
func Encode(data []byte) string {
	return encoding.EncodeToString(data)
}

// Token is an unforgeable set of data + expiration + signature, which can be
// verified by the Mint which created it (or any with the same secret key).
type Token struct {
	Data      []byte
	Expiry    time.Time
	Signature []byte
}

// String serializes a Token in a way suitable for use in a HTTP Cookie or URL.
func (t Token) String() string {
	return Encode(t.Data) + sep + t.Expiry.Format(timeLayout) + sep + Encode(t.Signature)
}

// FromString parses a serialization into a Token. A nil error indicates ONLY
// serialization success, NOT the validity of the Token. For that, use
// Mint.VerifyString.
func FromString(s string) (Token, error) {
	t := Token{}
	parts := strings.Split(s, sep)
	if len(parts) != 3 {
		return t, fmt.Errorf("%w (%w): %d parts, expect 3", ErrParse, ErrFormat, len(parts))
	}

	// Decode Data field.
	data, err := encoding.DecodeString(parts[0])
	if err != nil {
		return t, fmt.Errorf("%w (%w): %w (%s)", ErrParse, ErrDecoding, ErrFieldData, parts[0])
	}
	t.Data = data

	// Decode Expiry field.
	expiry, err := time.ParseInLocation(timeLayout, parts[1], time.Local)
	if err != nil {
		return t, fmt.Errorf("%w: %w (%s)", ErrParse, ErrFieldExpiry, parts[1])
	}
	t.Expiry = expiry

	// Decode Signature.
	sig, err := encoding.DecodeString(parts[2])
	if err != nil {
		return t, fmt.Errorf("%w (%w): %w (%s)", ErrParse, ErrDecoding, ErrFieldSignature, parts[2])
	}
	t.Signature = sig

	return t, nil
}

// Mint is used for constructing and verifying Tokens. The zero-value will
// generate a random secret the first time it needs to sign something, which
// then remains stable for its lifetime. Use NewMint to initialize the secret to
// something predictable.
type Mint struct {
	secret []byte
	once   sync.Once
}

// NewMint creates a Mint from the given secret. Any Mint instance with the same
// secret will product identical tokens if all parameters are the same.
func NewMint(secret []byte) *Mint {
	return &Mint{
		secret: secret,
	}
}

// Generate creates a signed Token whose Data is a cryptographically random byte
// slice of the length provided. The Token will expire at the given time.
func (m *Mint) Generate(dataLen int, expires time.Time) (Token, error) {
	data := make([]byte, dataLen)
	if _, err := rand.Read(data); err != nil {
		return Token{}, fmt.Errorf("Mint.Generate, rand.Read(data): %w", err)
	}
	return m.Sign(data, expires)
}

// Sign generates a valid Token which expires at the given time.
func (m *Mint) Sign(data []byte, expires time.Time) (Token, error) {
	t := Token{
		Data:   data,
		Expiry: expires,
	}
	sig, err := m.createSignature(data, expires)
	if err != nil {
		return t, fmt.Errorf("Mint.Sign, could not create signature: %w", err)
	}
	t.Signature = sig
	return t, nil
}

// VerifyString returns a Token from the serialized format and checks its
// validity. See Mint.Verify.
func (m *Mint) VerifyString(s string) (Token, error) {
	b, err := FromString(s)
	if err != nil {
		return b, err
	}
	return m.Verify(b)
}

// Verify checks Token validity (both signature and expiry).
func (m *Mint) Verify(b Token) (Token, error) {
	// Check expiration, if this is bad no signature check needed.
	if time.Now().After(b.Expiry) {
		return b, ErrVerifyExpiry
	}
	// Check signature matches.
	sig, err := m.createSignature(b.Data, b.Expiry)
	if err != nil {
		return b, fmt.Errorf("Mint.Verify, could not create signature: %w", err)
	}
	sigOK := hmac.Equal(b.Signature, sig)
	if !sigOK {
		return b, ErrVerifySignature
	}
	return b, nil
}

// createSignature is the internal signing method.
func (m *Mint) createSignature(data []byte, expires time.Time) ([]byte, error) {
	// This check makes the zero-value of Mint still usable and allows a
	// zero-config minter/checker without specifying the secret.
	m.once.Do(func() {
		if m.secret == nil {
			m.secret = make([]byte, 256)
			// NOTE: I don't particularly like the panic but my assumption is
			// that rand.Read failing is extremely unlikely.
			if _, err := rand.Read(m.secret); err != nil {
				panic(fmt.Errorf("rand.Read(Mint.secret): %w", err))
			}
		}
	})
	// Use a binary form of the unix timestamp.
	timeBuf := make([]byte, 8) // 64-bit integer
	binary.BigEndian.PutUint64(timeBuf, uint64(expires.Unix()))

	hash := hmac.New(sha256.New, m.secret)
	if _, err := hash.Write(data); err != nil {
		return nil, fmt.Errorf("hash.Write(data): %w", err)
	}
	if _, err := hash.Write(timeBuf); err != nil {
		return nil, fmt.Errorf("hash.Write(expiry): %w", err)
	}
	return hash.Sum(nil), nil
}

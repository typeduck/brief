package brief_test

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/typeduck/brief"
)

// TestTokenBasics does some general
func TestTokenBasics(t *testing.T) {
	m := brief.Mint{}
	for len := 10; len < 1000; len += 10 {
		for i := 0; i < 10; i++ {
			b, err := m.Generate(len, time.Now().Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = m.Verify(b); err != nil {
				t.Log(b)
				t.Fatal(err)
			}
			// Check that VerifyString works, too.
			s := b.String()
			b2, err := m.VerifyString(s)
			if err != nil {
				t.Log(s)
				t.Log(b)
				t.Fatal(err)
			}
			// Check that the Encode function gives same result.
			if !strings.HasPrefix(s, brief.Encode(b2.Data)) {
				t.Log(s)
				t.Log(brief.Encode(b2.Data))
				t.Fatal("Encode gave me mismatch")
			}
			// Check that an altered time would be detected!
			b.Expiry = b.Expiry.Add(time.Second)
			if _, err = m.Verify(b); !errors.Is(err, brief.ErrVerifySignature) {
				t.Log(b)
				t.Fatal("altered timestamp accepted as valid")
			}
			// Check that altered  data would be detected!
			b.Data = b.Data[1:]
			if _, err = m.Verify(b); !errors.Is(err, brief.ErrVerifySignature) {
				t.Log(b)
				t.Fatal("altered data accepted as valid")
			}
		}
	}
}

// TestTokenExpiryEdgeCase tests boundaries of expiration. We don't test on
// exact time.Now because this could fail expectations when we are right on the
// boundary, one-second granularity is good enough.
func TestTokenExpiryEdgeCase(t *testing.T) {
	mint := brief.Mint{}
	tok, err := mint.Generate(20, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mint.Verify(tok); err != nil {
		t.Fatal(err)
	}

	tok, err = mint.Generate(20, time.Now().Add(-time.Second))
	_, err = mint.Verify(tok)
	if !errors.Is(err, brief.ErrVerifyExpiry) {
		t.Fatal(fmt.Errorf("expected expiration error (%s)", brief.ErrVerifyExpiry))
	}
}

// BenchmarkSign benchmarks the Mint.Sign method.
func BenchmarkSignAndVerify(b *testing.B) {
	mint := brief.Mint{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token, err := mint.Generate(15, time.Now().Add(time.Second*5))
		if err != nil {
			b.Error("Sign failed:", err)
		}
		tok, err := mint.VerifyString(token.String())
		if err != nil {
			b.Error("Verify failed:", err, tok)
		}
	}
}

// This test caught a bug I predicted when running under race conditions, before
// adding sync.Once:
//
// `go test -run Concurrent -count=100 -race ./...`
func TestZeroValueMintConcurrentAccess(t *testing.T) {
	var m brief.Mint // zero-value Mint
	var wg sync.WaitGroup
	tokenChannel := make(chan string, 100) // Buffer to avoid blocking on token send

	// Number of concurrent accesses
	concurrentAccesses := 100

	wg.Add(concurrentAccesses)
	for i := 0; i < concurrentAccesses; i++ {
		go func() {
			defer wg.Done()
			// Attempt to generate a token with the zero-value Mint
			token, err := m.Generate(1, time.Now().Add(1*time.Hour))
			if err != nil {
				t.Errorf("Failed to sign string: %v", err)
			}
			tokenChannel <- token.String()
		}()
	}
	wg.Wait() // Wait for all goroutines to finish
	close(tokenChannel)

	// Verify that all tokens are correct.
	for token := range tokenChannel {
		tok, err := m.VerifyString(token)
		if err != nil {
			t.Errorf("invalid token in concurrent access: %s (%s)", err, tok)
		}
	}
}

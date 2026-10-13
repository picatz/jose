package header_test

import (
	"testing"

	"github.com/picatz/jose/pkg/header"
)

// RFC 7515 §4.1.11: a recipient that does not understand a critical
// extension must reject the object, and no extensions are understood unless
// the application says so.
func TestCriticalHeadersRejectedByDefault(t *testing.T) {
	h := header.Parameters{
		header.Algorithm: "ES256",
		header.Critical:  []any{"exp-ext"},
		"exp-ext":        true,
	}
	if err := h.ValidateCriticalHeaders(nil); err == nil {
		t.Fatal("nil supported list accepted an unknown critical extension")
	}
	if err := h.ValidateCriticalHeaders([]string{}); err == nil {
		t.Fatal("empty supported list accepted an unknown critical extension")
	}
	if err := h.ValidateCriticalHeaders([]string{"exp-ext"}); err != nil {
		t.Fatalf("declared extension rejected: %v", err)
	}
}

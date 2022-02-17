package jwt

import (
	"errors"
	"fmt"
)

var (
	ErrNoClaimSet = errors.New("no claim set")
)

type ErrSigningFailed struct {
	Inner error
}

func (e *ErrSigningFailed) Error() string {
	return fmt.Sprintf("signing failed: %v", e.Inner)
}

func (e *ErrSigningFailed) Unwrap() error {
	return e.Inner
}

func NewSigningError(inner error) *ErrSigningFailed {
	return &ErrSigningFailed{Inner: inner}
}

type ErrInvalidType struct {
	Inner error
}

func (e *ErrInvalidType) Error() string {
	return fmt.Sprintf("signing failed: %v", e.Inner)
}

func (e *ErrInvalidType) Unwrap() error {
	return e.Inner
}

func NewInvalidTypeError(inner error) *ErrInvalidType {
	return &ErrInvalidType{Inner: inner}
}

package jwa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewAllowedAlgorithms(t *testing.T) {
	def := DefaultAllowedAlgorithms()

	tests := []struct {
		Name    string
		Allowed []Algorithm
		Require func(t *testing.T, algs AllowedAlgorithms)
	}{
		{
			Name:    "none allowed",
			Allowed: []Algorithm{},
			Require: func(t *testing.T, algs AllowedAlgorithms) {
				require.Empty(t, algs)
				require.Empty(t, algs.List())
				require.False(t, algs.Allowed(def.List()...))
			},
		},
		{
			Name:    "default allowed",
			Allowed: DefaultAllowedAlgorithms().List(),
			Require: func(t *testing.T, algs AllowedAlgorithms) {
				require.NotEmpty(t, algs)
				require.NotEmpty(t, algs.List())
				require.Equal(t, 2, len(algs))
				require.True(t, algs.Allowed(def.List()...))
				require.False(t, algs.Allowed(HS256))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			algs := NewAllowedAlgorithms(test.Allowed...)
			if test.Require != nil {
				test.Require(t, algs)
			}
		})
	}

}

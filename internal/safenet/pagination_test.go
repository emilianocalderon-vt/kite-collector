package safenet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPaginationGuard(t *testing.T) {
	t.Run("allows up to max iterations", func(t *testing.T) {
		g := NewPaginationGuard()
		for i := 0; i < MaxPaginationIterations; i++ {
			require.NoError(t, g.Next(), "iteration %d should succeed", i+1)
		}
	})

	t.Run("rejects beyond max", func(t *testing.T) {
		g := NewPaginationGuard()
		for i := 0; i < MaxPaginationIterations; i++ {
			require.NoError(t, g.Next())
		}
		err := g.Next()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pagination exceeded")
	})

	t.Run("fresh guard starts at zero", func(t *testing.T) {
		g := NewPaginationGuard()
		assert.Equal(t, 0, g.current)
		assert.Equal(t, MaxPaginationIterations, g.max)
	})
}

package safenet

import "fmt"

// MaxPaginationIterations is the hard limit on pagination loops.
const MaxPaginationIterations = 10_000

// PaginationGuard tracks iteration count and prevents infinite loops.
type PaginationGuard struct {
	max     int
	current int
}

// NewPaginationGuard returns a guard with the default max iterations.
func NewPaginationGuard() *PaginationGuard {
	return &PaginationGuard{max: MaxPaginationIterations}
}

// Next increments the counter and returns an error if the limit is exceeded.
func (g *PaginationGuard) Next() error {
	g.current++
	if g.current > g.max {
		return fmt.Errorf("pagination exceeded %d iterations — "+
			"possible infinite loop or API reporting incorrect totals", g.max)
	}
	return nil
}

package strategy

import (
	"errors"
	"fmt"
	"slices"
	"sync"
)

var (
	mu       sync.RWMutex                // guards registry
	registry = make(map[string]Strategy) // strategies by name
)

// ErrUnknown is returned by Get for a name nobody registered.
var ErrUnknown = errors.New("strategy: unknown strategy")

// Register adds s under its name. It is meant to be called from init
// functions; registering a nil strategy, a nameless one or the same name
// twice is a programming error, so it panics, as database/sql.Register does.
func Register(s Strategy) {
	if s == nil {
		panic("strategy: Register of a nil Strategy")
	}
	if s.Name() == "" {
		panic("strategy: Register of a Strategy with no name")
	}

	mu.Lock()
	defer mu.Unlock()
	if _, ok := registry[s.Name()]; ok {
		panic("strategy: Register called twice for " + s.Name())
	}
	registry[s.Name()] = s
}

// Get returns the strategy registered under name, or an error wrapping
// ErrUnknown.
func Get(name string) (Strategy, error) {
	mu.RLock()
	defer mu.RUnlock()
	s, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknown, name)
	}
	return s, nil
}

// Names returns the names of all registered strategies, sorted, so the
// order is the same on every call.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

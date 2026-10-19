package strategy

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
)

// fakeStrategy is a do-nothing strategy with a chosen name. Tests register
// it under names starting with "test-" so they never clash with real ones.
type fakeStrategy string

func (f fakeStrategy) Name() string               { return string(f) }
func (fakeStrategy) Apply(net.Conn, []byte) error { return nil }

// mustPanic runs f and returns the panic message, failing the test if f
// does not panic.
func mustPanic(t *testing.T, f func()) (msg string) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("did not panic")
		}
		msg = fmt.Sprint(r)
	}()
	f()
	return ""
}

func TestRegisterAndGet(t *testing.T) {
	Register(fakeStrategy("test-get"))

	s, err := Get("test-get")
	if err != nil {
		t.Fatalf("Get(test-get) error = %v", err)
	}
	if s.Name() != "test-get" {
		t.Errorf("Get(test-get).Name() = %q", s.Name())
	}
}

func TestGetUnknown(t *testing.T) {
	s, err := Get("spilt")
	if s != nil || !errors.Is(err, ErrUnknown) {
		t.Fatalf("Get(spilt) = %v, %v; want nil, ErrUnknown", s, err)
	}
	if !strings.Contains(err.Error(), `"spilt"`) {
		t.Errorf("error %q does not name the strategy", err)
	}
}

func TestRegisterTwicePanics(t *testing.T) {
	Register(fakeStrategy("test-twice"))
	msg := mustPanic(t, func() { Register(fakeStrategy("test-twice")) })
	if !strings.Contains(msg, "test-twice") {
		t.Errorf("panic message %q does not name the strategy", msg)
	}
}

func TestRegisterNilPanics(t *testing.T) {
	mustPanic(t, func() { Register(nil) })
}

func TestRegisterNoNamePanics(t *testing.T) {
	mustPanic(t, func() { Register(fakeStrategy("")) })
}

func TestNames(t *testing.T) {
	Register(fakeStrategy("test-names-b"))
	Register(fakeStrategy("test-names-a"))

	names := Names()
	if !slices.IsSorted(names) {
		t.Errorf("Names() = %q; want it sorted", names)
	}
	if slices.Contains(names, "") {
		t.Errorf("Names() = %q; contains an empty name", names)
	}
	for _, want := range []string{"baseline", "test-names-a", "test-names-b"} {
		if !slices.Contains(names, want) {
			t.Errorf("Names() = %q; missing %q", names, want)
		}
	}
	for range 20 { // map order is random; the list must not be
		if again := Names(); !slices.Equal(again, names) {
			t.Fatalf("Names() changed between calls: %q then %q", names, again)
		}
	}
}

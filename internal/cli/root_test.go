package cli

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// run executes the command tree with args and returns everything it printed.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd("1.2.3")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args) // use these instead of os.Args
	err := cmd.Execute()
	return out.String(), err
}

func TestRootCmd(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		want     string // if set, the output must equal this
		contains string // if set, the output must contain this
		wantErr  bool
	}{
		{"version command", []string{"version"}, "dpiprisma 1.2.3\n", "", false},
		{"version flag", []string{"--version"}, "dpiprisma 1.2.3\n", "", false},
		// An empty slice, not nil: SetArgs(nil) makes cobra fall back to os.Args, i.e. go test's own flags.
		{"no args shows help", []string{}, "", "Usage:", false},
		{"unknown command", []string{"bogus"}, "", "", true},
		{"version rejects args", []string{"version", "extra"}, "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := run(t, tt.args...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v; wantErr %v", err, tt.wantErr)
			}
			if tt.want != "" && got != tt.want {
				t.Errorf("output = %q; want %q", got, tt.want)
			}
			if tt.contains != "" && !strings.Contains(got, tt.contains) {
				t.Errorf("output = %q; want it to contain %q", got, tt.contains)
			}
		})
	}
}

func TestNewLogger(t *testing.T) {
	var quiet bytes.Buffer
	l := newLogger(&quiet, false)
	l.Debug("debug message")
	l.Warn("warn message")
	if strings.Contains(quiet.String(), "debug message") {
		t.Errorf("quiet logger printed a debug message: %q", quiet.String())
	}
	if !strings.Contains(quiet.String(), "warn message") {
		t.Errorf("quiet logger hid a warning: %q", quiet.String())
	}

	var loud bytes.Buffer
	l = newLogger(&loud, true)
	l.Debug("debug message")
	if !strings.Contains(loud.String(), "debug message") {
		t.Errorf("verbose logger hid a debug message: %q", loud.String())
	}
}

func TestVerboseFlag(t *testing.T) {
	// The command replaces the global logger; put the old one back afterwards.
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })

	out, err := run(t, "-v", "version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "msg=starting") {
		t.Errorf("-v output = %q; want a debug line", out)
	}

	out, err = run(t, "version")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "msg=starting") {
		t.Errorf("output without -v = %q; want no debug line", out)
	}
}

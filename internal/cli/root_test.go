package cli

import (
	"bytes"
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

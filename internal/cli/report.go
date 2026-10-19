package cli

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/mehmetalitilgen/dpiprisma/internal/report"
	"github.com/spf13/cobra"
)

// readResults decodes the JSON file at path into a list of T. The file may
// hold a list, as "scan --json" writes, or a single object, as
// "locate --json" writes.
func readResults[T any](path string) ([]T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	trimmed := bytes.TrimSpace(toUTF8(data))
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var one T
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return []T{one}, nil
	}

	var list []T
	if err := json.Unmarshal(trimmed, &list); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return list, nil
}

// toUTF8 undoes what shell redirection may have done to a JSON file:
// Windows PowerShell 5.1's ">" writes UTF-16 with a byte order mark, and
// some editors put a mark in front of UTF-8. Anything else is returned as is.
func toUTF8(data []byte) []byte {
	var order binary.ByteOrder
	switch {
	case bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}):
		return data[3:]
	case bytes.HasPrefix(data, []byte{0xFF, 0xFE}):
		order = binary.LittleEndian
	case bytes.HasPrefix(data, []byte{0xFE, 0xFF}):
		order = binary.BigEndian
	default:
		return data
	}

	units := make([]uint16, 0, len(data)/2)
	for i := 2; i+1 < len(data); i += 2 {
		units = append(units, order.Uint16(data[i:]))
	}
	return []byte(string(utf16.Decode(units)))
}

// readAll appends the results of every file in paths to dst.
func readAll[T any](dst []T, paths []string) ([]T, error) {
	for _, p := range paths {
		list, err := readResults[T](p)
		if err != nil {
			return nil, err
		}
		dst = append(dst, list...)
	}
	return dst, nil
}

// reportFormat picks the output format: the --format flag if set, otherwise
// the extension of the output file, otherwise Markdown.
func reportFormat(format, output string) (string, error) {
	if format == "" {
		switch strings.ToLower(filepath.Ext(output)) {
		case ".html", ".htm":
			return "html", nil
		default:
			return "md", nil
		}
	}
	switch format {
	case "md", "html":
		return format, nil
	}
	return "", fmt.Errorf("--format must be md or html, got %q", format)
}

// newReportCmd builds "dpiprisma report".
func newReportCmd(version string) *cobra.Command {
	var (
		scanFiles   []string
		locateFiles []string
		matrixFiles []string
		format      string
		output      string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Write a Markdown or HTML report from saved scan, locate and matrix results",
		Example: `  dpiprisma scan --json x.com > scan.json
  dpiprisma locate --json x.com > locate.json
  dpiprisma report --scan scan.json --locate locate.json -o report.html`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(scanFiles)+len(locateFiles)+len(matrixFiles) == 0 {
				return fmt.Errorf("give at least one of --scan, --locate or --matrix")
			}
			kind, err := reportFormat(format, output)
			if err != nil {
				return err
			}

			r := report.Results{Generated: time.Now().UTC(), Version: version}
			if r.Scan, err = readAll(r.Scan, scanFiles); err != nil {
				return err
			}
			if r.Locate, err = readAll(r.Locate, locateFiles); err != nil {
				return err
			}
			if r.Matrix, err = readAll(r.Matrix, matrixFiles); err != nil {
				return err
			}

			// Render into memory first, so a failure never leaves a
			// half-written report file behind.
			var buf bytes.Buffer
			if kind == "html" {
				err = report.HTML(&buf, r)
			} else {
				err = report.Markdown(&buf, r)
			}
			if err != nil {
				return err
			}

			if output == "" {
				_, err = io.Copy(cmd.OutOrStdout(), &buf)
				return err
			}
			return os.WriteFile(output, buf.Bytes(), 0o644)
		},
	}

	cmd.Flags().StringSliceVar(&scanFiles, "scan", nil, "JSON file written by \"scan --json\" (repeatable)")
	cmd.Flags().StringSliceVar(&locateFiles, "locate", nil, "JSON file written by \"locate --json\" (repeatable)")
	cmd.Flags().StringSliceVar(&matrixFiles, "matrix", nil, "JSON file written by \"matrix --json\" (repeatable)")
	cmd.Flags().StringVar(&format, "format", "", "md or html (default: from the -o extension, else md)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "file to write (default: standard output)")
	return cmd
}

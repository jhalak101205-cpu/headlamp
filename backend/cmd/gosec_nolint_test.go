/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// gosecRuleJustificationPattern matches a Gosec rule identifier (e.g., "G304: <rationale>")
// followed by a non-empty justification.
var gosecRuleJustificationPattern = regexp.MustCompile(`\bG[1-6][0-9]{2}:\s+\S+`)

// gosecLintFinding describes a production //nolint:gosec directive that is missing
// a Gosec rule identifier or justification.
type gosecLintFinding struct {
	File    string
	Line    int
	Comment string
	Reason  string
}

func (f gosecLintFinding) String() string {
	return fmt.Sprintf("%s:%d: %s (%s)", f.File, f.Line, f.Reason, strings.TrimSpace(f.Comment))
}

// isPackageLevelDirective reports whether a comment at pos appears before the
// file's "package" declaration (e.g., adapted third-party files with file-wide
// multi-linter suppressions).
func isPackageLevelDirective(file *ast.File, commentPos token.Pos) bool {
	return file != nil && file.Package.IsValid() && commentPos < file.Package
}

// extractNolintGosecExplanation inspects a raw single-line ("//...") or block ("/*...*/")
// comment. If the comment contains a nolint directive targeting "gosec" (or bare "//nolint"),
// it returns (true, explanationText, isBareNolint).
func extractNolintGosecExplanation(raw string) (targetsGosec bool, explanation string, isBare bool) {
	trimmed := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(trimmed, "//"):
		trimmed = strings.TrimPrefix(trimmed, "//")
	case strings.HasPrefix(trimmed, "/*") && strings.HasSuffix(trimmed, "*/"):
		trimmed = strings.TrimSuffix(strings.TrimPrefix(trimmed, "/*"), "*/")
	default:
		return false, "", false
	}

	// No space allowed between "//" and "nolint" per standard golangci-lint directive syntax,
	// though we also check after trimming leading spaces to catch malformed variations.
	trimmedLeft := strings.TrimLeft(trimmed, " \t")
	if !strings.HasPrefix(trimmedLeft, "nolint") {
		return false, "", false
	}

	rest := strings.TrimPrefix(trimmedLeft, "nolint")

	// A comment starting with "nolint" followed by letters (e.g., "//nolinting") is not a directive.
	if rest != "" && rest[0] != ':' && rest[0] != ' ' && rest[0] != '\t' && !strings.HasPrefix(rest, "//") {
		return false, "", false
	}

	// Split directive part from inline "// explanation" if present.
	var linterSpec string

	if idx := strings.Index(rest, "//"); idx >= 0 {
		linterSpec = strings.TrimSpace(rest[:idx])
		explanation = strings.TrimSpace(rest[idx+2:])
	} else {
		linterSpec = strings.TrimSpace(rest)
	}

	// Bare //nolint (or //nolint // explanation) suppresses all linters including gosec.
	if linterSpec == "" || !strings.HasPrefix(linterSpec, ":") {
		return true, explanation, true
	}

	linterList := strings.TrimPrefix(linterSpec, ":")
	// If someone wrote "//nolint:gosec some explanation without //", separate at whitespace.
	if fields := strings.Fields(linterList); len(fields) > 0 {
		linterList = fields[0]
		if explanation == "" && len(fields) > 1 {
			explanation = strings.Join(fields[1:], " ")
		}
	}

	for _, l := range strings.Split(linterList, ",") {
		name := strings.TrimSpace(l)
		if name == "gosec" || name == "all" {
			return true, explanation, false
		}
	}

	return false, "", false
}

// inspectGoSourceForGosecNolint parses Go source bytes and validates all production
// //nolint directives that suppress gosec.
func inspectGoSourceForGosecNolint(filename string, src []byte) ([]gosecLintFinding, error) {
	fset := token.NewFileSet()

	file, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", filename, err)
	}

	var findings []gosecLintFinding

	for _, group := range file.Comments {
		for _, comment := range group.List {
			if isPackageLevelDirective(file, comment.Pos()) {
				continue
			}

			targetsGosec, explanation, isBare := extractNolintGosecExplanation(comment.Text)
			if !targetsGosec {
				continue
			}

			pos := fset.Position(comment.Pos())

			if isBare {
				findings = append(findings, gosecLintFinding{
					File:    filename,
					Line:    pos.Line,
					Comment: comment.Text,
					Reason:  "bare //nolint is not allowed; specify the linter and Gosec rule ID (e.g. //nolint:gosec // G304: <justification>)",
				})

				continue
			}

			if explanation == "" {
				findings = append(findings, gosecLintFinding{
					File:    filename,
					Line:    pos.Line,
					Comment: comment.Text,
					Reason:  "//nolint:gosec is missing an inline justification with a Gosec rule ID (e.g. //nolint:gosec // G304: <justification>)",
				})

				continue
			}

			if !gosecRuleJustificationPattern.MatchString(explanation) {
				findings = append(findings, gosecLintFinding{
					File:    filename,
					Line:    pos.Line,
					Comment: comment.Text,
					Reason:  "//nolint:gosec justification must include a specific Gosec rule ID (G101-G602) followed by a colon and rationale (e.g. //nolint:gosec // G304: <justification>)",
				})
			}
		}
	}

	return findings, nil
}

// scanProductionGoFiles walks rootDirs and inspects all non-test .go files.
func scanProductionGoFiles(rootDirs ...string) ([]gosecLintFinding, error) {
	var allFindings []gosecLintFinding

	for _, root := range rootDirs {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

			if entry.IsDir() {
				name := entry.Name()
				if name == "vendor" || name == "testdata" || name == "headlamp_testdata" || strings.HasPrefix(name, ".") {
					return filepath.SkipDir
				}

				return nil
			}

			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			//nolint:gosec // Walking local repository Go source files under controlled directory roots.
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			findings, err := inspectGoSourceForGosecNolint(path, src)
			if err != nil {
				return err
			}

			allFindings = append(allFindings, findings...)

			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	slices.SortFunc(allFindings, func(a, b gosecLintFinding) int {
		if a.File != b.File {
			return strings.Compare(a.File, b.File)
		}

		return a.Line - b.Line
	})

	return allFindings, nil
}

// TestProductionGosecSuppressionsHaveRuleIDs enforces that every production //nolint:gosec
// suppression in backend/cmd and backend/pkg documents a specific Gosec rule identifier
// (e.g. G304, G402, G124) and trust-boundary rationale.
func TestProductionGosecSuppressionsHaveRuleIDs(t *testing.T) {
	findings, err := scanProductionGoFiles(".", "../pkg")
	if err != nil {
		t.Fatalf("failed to scan production Go files: %v", err)
	}

	if len(findings) > 0 {
		var msg strings.Builder
		msg.WriteString("found production //nolint:gosec suppressions without a specific Gosec rule ID and justification:\n")

		for _, f := range findings {
			msg.WriteString("  - ")
			msg.WriteString(f.String())
			msg.WriteByte('\n')
		}

		t.Fatal(msg.String())
	}
}

//nolint:funlen // Table-driven unit test covers all nolint:gosec syntax and edge cases.
func TestInspectGoSourceForGosecNolintEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		src          string
		wantFindings int
		wantReason   string
	}{
		{
			name: "valid single gosec directive with rule ID and justification",
			src: `package sample
func read() {
	//nolint:gosec // G304: Path configured via operator CLI flags.
	_ = 1
}`,
			wantFindings: 0,
		},
		{
			name: "valid inline gosec directive with multiple rule IDs",
			src: `package sample
func read() {
	_ = 1 //nolint:gosec // G304, G306: Controlled temporary path and permissions.
}`,
			wantFindings: 0,
		},
		{
			name: "valid multi-linter directive including gosec with rule ID",
			src: `package sample
func read() {
	//nolint:funlen,gosec // G402: Operator opted in via --insecure-ssl for OIDC.
	_ = 1
}`,
			wantFindings: 0,
		},
		{
			name: "non-gosec nolint directive is ignored",
			src: `package sample
//nolint:funlen // Handler wires all routes and middleware.
func setup() {}`,
			wantFindings: 0,
		},
		{
			name: "package-level adapted file directive before package declaration is exempt",
			src: `//nolint:funlen,gosec,govet // Preserve adapted upstream client-go implementation.
package sample
func run() {}`,
			wantFindings: 0,
		},
		{
			name: "string literal containing //nolint:gosec is ignored by AST parser",
			src: `package sample
const help = "//nolint:gosec without rule ID inside string literal"`,
			wantFindings: 0,
		},
		{
			name: "ordinary comment mentioning nolintinting is ignored",
			src: `package sample
// nolinting is discussed in docs
func run() {}`,
			wantFindings: 0,
		},
		{
			name: "missing justification on nolint:gosec is rejected",
			src: `package sample
func read() {
	_ = 1 //nolint:gosec
}`,
			wantFindings: 1,
			wantReason:   "missing an inline justification",
		},
		{
			name: "justification without Gosec rule ID is rejected",
			src: `package sample
func read() {
	_ = 1 //nolint:gosec // Path comes from operator CLI flag.
}`,
			wantFindings: 1,
			wantReason:   "must include a specific Gosec rule ID",
		},
		{
			name: "rule ID without rationale after colon is rejected",
			src: `package sample
func read() {
	_ = 1 //nolint:gosec // G304:
}`,
			wantFindings: 1,
			wantReason:   "must include a specific Gosec rule ID",
		},
		{
			name: "invalid Gosec rule number (G999) is rejected",
			src: `package sample
func read() {
	_ = 1 //nolint:gosec // G999: Invalid rule category.
}`,
			wantFindings: 1,
			wantReason:   "must include a specific Gosec rule ID",
		},
		{
			name: "multi-linter directive with gosec but no Gosec rule ID is rejected",
			src: `package sample
func read() {
	//nolint:errcheck,gosec // Error and security check intentionally skipped.
	_ = 1
}`,
			wantFindings: 1,
			wantReason:   "must include a specific Gosec rule ID",
		},
		{
			name: "bare nolint directive is rejected",
			src: `package sample
func read() {
	_ = 1 //nolint // suppresses everything
}`,
			wantFindings: 1,
			wantReason:   "bare //nolint is not allowed",
		},
		{
			name: "nolint:all without Gosec rule ID is rejected",
			src: `package sample
func read() {
	_ = 1 //nolint:all // suppresses all linters
}`,
			wantFindings: 1,
			wantReason:   "must include a specific Gosec rule ID",
		},
		{
			name: "block comment nolint:gosec without rule ID is rejected",
			src: `package sample
func read() {
	_ = 1 /*nolint:gosec // missing rule id */
}`,
			wantFindings: 1,
			wantReason:   "must include a specific Gosec rule ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := inspectGoSourceForGosecNolint("sample.go", []byte(tt.src))
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}

			if len(findings) != tt.wantFindings {
				t.Fatalf("got %d findings (%v), want %d", len(findings), findings, tt.wantFindings)
			}

			if tt.wantReason != "" && !strings.Contains(findings[0].Reason, tt.wantReason) {
				t.Errorf("finding reason %q does not contain %q", findings[0].Reason, tt.wantReason)
			}
		})
	}
}

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// secretIdentifiers are the fields and variables that hold service secrets.
// None of them may be passed to a logging or printing call.
var secretIdentifiers = regexp.MustCompile(`^(smtpPassword|managementAPIKey|ManagementAPIKey|tmfAdminToken|TMFAdminToken|TSAPassword|ClientSecret|adminPassword|Password)$`)

// TestNoSecretsInLogCalls is a regression test for ISBECORE-478: it parses
// every non-test Go file and fails if a slog/fmt/log call receives a secret field
// (e.g. slog.Debug("token", "token", s.smtpPassword)). Logging whether a secret
// is set (s.smtpPassword != "") is allowed.
func TestNoSecretsInLogCalls(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isLogCall(call) {
				return true
			}
			for _, arg := range call.Args {
				if id := secretArg(arg); id != "" {
					t.Errorf("%s: %s is passed to a logging call", fset.Position(arg.Pos()), id)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func isLogCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		// Logger values such as logger.Info(...) or s.log().Error(...).
		switch sel.Sel.Name {
		case "Debug", "Info", "Warn", "Error", "Log", "With":
			return true
		}
		return false
	}
	switch pkg.Name {
	case "slog", "log":
		return true
	case "fmt":
		return strings.HasPrefix(sel.Sel.Name, "Print") || strings.HasPrefix(sel.Sel.Name, "Fprint")
	}
	return false
}

// secretArg returns the secret identifier when the argument is that value itself
// (x.smtpPassword, password, string(x.Password)); comparisons such as
// x.smtpPassword != "" are not secrets.
func secretArg(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		if secretIdentifiers.MatchString(v.Sel.Name) {
			return v.Sel.Name
		}
	case *ast.Ident:
		if secretIdentifiers.MatchString(v.Name) {
			return v.Name
		}
	case *ast.CallExpr:
		for _, a := range v.Args {
			if id := secretArg(a); id != "" {
				return id
			}
		}
	case *ast.ParenExpr:
		return secretArg(v.X)
	}
	return ""
}

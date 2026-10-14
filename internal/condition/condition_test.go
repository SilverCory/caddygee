package condition_test

import (
	"testing"

	"caddygee/internal/condition"
)

func TestParse_VerbEqual(t *testing.T) {
	node, err := condition.Parse(`request.verb = "GET"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c, ok := node.(condition.Comparison)
	if !ok {
		t.Fatalf("expected Comparison, got %T", node)
	}
	if c.Left != "request.verb" || c.Op != "=" || c.Right != "GET" {
		t.Errorf("got {%q %q %q}", c.Left, c.Op, c.Right)
	}
}

func TestParse_AndExpression(t *testing.T) {
	node, err := condition.Parse(`(request.verb = "GET") and (proxy.pathsuffix MatchesPath "/users")`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bin, ok := node.(condition.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", node)
	}
	if bin.Op != "and" {
		t.Errorf("expected op=and, got %q", bin.Op)
	}
}

func TestParse_OrExpression(t *testing.T) {
	node, err := condition.Parse(`request.verb = "GET" or request.verb = "HEAD"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bin, ok := node.(condition.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", node)
	}
	if bin.Op != "or" {
		t.Errorf("expected op=or, got %q", bin.Op)
	}
}

func TestParse_NotExpression(t *testing.T) {
	node, err := condition.Parse(`not request.verb = "DELETE"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := node.(condition.UnaryOp); !ok {
		t.Fatalf("expected UnaryOp, got %T", node)
	}
}

func TestParse_Empty(t *testing.T) {
	node, err := condition.Parse("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node != nil {
		t.Errorf("expected nil node for empty string, got %T", node)
	}
}

func TestParse_PathSuffix(t *testing.T) {
	node, err := condition.Parse(`proxy.pathsuffix = "/users"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c, ok := node.(condition.Comparison)
	if !ok {
		t.Fatalf("expected Comparison, got %T", node)
	}
	if c.Right != "/users" {
		t.Errorf("right operand: got %q, want %q", c.Right, "/users")
	}
}

// --- matcher tests ---

func TestMatcher_VerbMethod(t *testing.T) {
	node, _ := condition.Parse(`request.verb = "POST"`)
	m := condition.ToCaddyMatcher(node)
	if len(m.Methods) != 1 || m.Methods[0] != "POST" {
		t.Errorf("methods: %v", m.Methods)
	}
	if len(m.Unsupported) != 0 {
		t.Errorf("unexpected unsupported: %v", m.Unsupported)
	}
}

func TestMatcher_PathSuffix(t *testing.T) {
	node, _ := condition.Parse(`proxy.pathsuffix MatchesPath "/users/*"`)
	m := condition.ToCaddyMatcher(node)
	if len(m.Paths) != 1 || m.Paths[0] != "/users/*" {
		t.Errorf("paths: %v", m.Paths)
	}
}

func TestMatcher_AndVerbPath(t *testing.T) {
	node, _ := condition.Parse(`(request.verb = "GET") and (proxy.pathsuffix MatchesPath "/users")`)
	m := condition.ToCaddyMatcher(node)
	if len(m.Methods) != 1 || m.Methods[0] != "GET" {
		t.Errorf("methods: %v", m.Methods)
	}
	if len(m.Paths) != 1 || m.Paths[0] != "/users" {
		t.Errorf("paths: %v", m.Paths)
	}
	if len(m.Unsupported) != 0 {
		t.Errorf("unexpected unsupported: %v", m.Unsupported)
	}
}

func TestMatcher_HeaderComparison(t *testing.T) {
	node, _ := condition.Parse(`request.header.x-api-key = "secret"`)
	m := condition.ToCaddyMatcher(node)
	if m.Headers["X-Api-Key"] != "secret" {
		t.Errorf("headers: %v", m.Headers)
	}
}

func TestMatcher_OrUnsupported(t *testing.T) {
	node, _ := condition.Parse(`request.verb = "GET" or request.verb = "HEAD"`)
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) == 0 {
		t.Error("expected unsupported entry for OR condition")
	}
}

func TestMatcher_UnknownVariable(t *testing.T) {
	node, _ := condition.Parse(`some.unknown.var = "foo"`)
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) == 0 {
		t.Error("expected unsupported entry for unknown variable")
	}
}

func TestMatcher_Nil(t *testing.T) {
	m := condition.ToCaddyMatcher(nil)
	if len(m.Methods) != 0 || len(m.Paths) != 0 {
		t.Error("nil node should produce empty matcher")
	}
}

func TestMatcher_JavaRegex(t *testing.T) {
	node, err := condition.Parse(`proxy.pathsuffix JavaRegex "/users/[0-9]+"`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) == 0 {
		t.Error("expected unsupported entry for JavaRegex condition")
	}
}

func TestMatcher_NotUnsupported(t *testing.T) {
	node, err := condition.Parse(`not request.verb = "DELETE"`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) == 0 {
		t.Error("expected unsupported entry for NOT condition")
	}
}

func TestParse_StartsWith(t *testing.T) {
	node, err := condition.Parse(`proxy.pathsuffix StartsWith "/api"`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	c, ok := node.(condition.Comparison)
	if !ok {
		t.Fatalf("expected Comparison, got %T", node)
	}
	if c.Op != "StartsWith" {
		t.Errorf("op: got %q, want %q", c.Op, "StartsWith")
	}
}

// --- NOT path exclusion tests ---

func TestMatcher_NotPath(t *testing.T) {
	node, err := condition.Parse(`!(proxy.pathsuffix MatchesPath "/docs/*")`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) != 0 {
		t.Errorf("unexpected unsupported: %v", m.Unsupported)
	}
	if len(m.ExcludePaths) != 1 || m.ExcludePaths[0] != "/docs/*" {
		t.Errorf("exclude_paths: got %v, want [\"/docs/*\"]", m.ExcludePaths)
	}
}

func TestMatcher_NotPathAnd(t *testing.T) {
	node, err := condition.Parse(`!(proxy.pathsuffix MatchesPath "/docs/*") AND !(proxy.pathsuffix MatchesPath "/openapi.json")`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) != 0 {
		t.Errorf("unexpected unsupported: %v", m.Unsupported)
	}
	if len(m.ExcludePaths) != 2 {
		t.Fatalf("exclude_paths: got %v, want 2 entries", m.ExcludePaths)
	}
	if m.ExcludePaths[0] != "/docs/*" || m.ExcludePaths[1] != "/openapi.json" {
		t.Errorf("exclude_paths: got %v", m.ExcludePaths)
	}
}

func TestMatcher_NotOrPaths(t *testing.T) {
	node, err := condition.Parse(`!(proxy.pathsuffix MatchesPath "/v1/notification/me" OR proxy.pathsuffix MatchesPath "/v1/notification/me/count")`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) != 0 {
		t.Errorf("unexpected unsupported: %v", m.Unsupported)
	}
	if len(m.ExcludePaths) != 2 {
		t.Fatalf("exclude_paths: got %v, want 2 entries", m.ExcludePaths)
	}
}

// --- environment.name silent drop tests ---

func TestMatcher_EnvironmentNameDropped(t *testing.T) {
	node, err := condition.Parse(`environment.name = "preview"`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) != 0 {
		t.Errorf("environment.name should be silently dropped, got unsupported: %v", m.Unsupported)
	}
	if len(m.Methods) != 0 || len(m.Paths) != 0 {
		t.Error("environment.name should produce empty matcher")
	}
}

func TestMatcher_EnvironmentNameWithPath(t *testing.T) {
	node, err := condition.Parse(`(proxy.pathsuffix MatchesPath "/v1/foo") AND (environment.name = "preview")`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) != 0 {
		t.Errorf("unexpected unsupported: %v", m.Unsupported)
	}
	if len(m.Paths) != 1 || m.Paths[0] != "/v1/foo" {
		t.Errorf("paths: got %v, want [\"/v1/foo\"]", m.Paths)
	}
}

// --- header Matches / StartsWith tests ---

func TestMatcher_HeaderMatches(t *testing.T) {
	node, err := condition.Parse(`request.header.Authorization Matches "Bearer *"`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) != 0 {
		t.Errorf("unexpected unsupported: %v", m.Unsupported)
	}
	want := "^Bearer .*$"
	if m.HeaderRegexp["Authorization"] != want {
		t.Errorf("header_regexp: got %q, want %q", m.HeaderRegexp["Authorization"], want)
	}
}

func TestMatcher_HeaderStartsWith(t *testing.T) {
	node, err := condition.Parse(`request.header.Authorization =| "Bearer"`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) != 0 {
		t.Errorf("unexpected unsupported: %v", m.Unsupported)
	}
	want := "^Bearer"
	if m.HeaderRegexp["Authorization"] != want {
		t.Errorf("header_regexp: got %q, want %q", m.HeaderRegexp["Authorization"], want)
	}
}

func TestMatcher_NotPathsWithNegatedHeaderStartsWith(t *testing.T) {
	// Real condition from supply-chain services
	node, err := condition.Parse(`!(proxy.pathsuffix MatchesPath "/docs/*") AND !(proxy.pathsuffix MatchesPath "/openapi.json") AND !(request.header.Authorization =| "Bearer")`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) != 0 {
		t.Errorf("unexpected unsupported: %v", m.Unsupported)
	}
	if len(m.ExcludePaths) != 2 {
		t.Errorf("exclude_paths: got %v, want 2 entries", m.ExcludePaths)
	}
	want := "^Bearer"
	if m.NegateHeaderRegexp["Authorization"] != want {
		t.Errorf("negate_header_regexp: got %q, want %q", m.NegateHeaderRegexp["Authorization"], want)
	}
}

func TestMatcher_NegatedHeaderMatches(t *testing.T) {
	node, err := condition.Parse(`!(request.header.authorization Matches "Bearer *")`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) != 0 {
		t.Errorf("unexpected unsupported: %v", m.Unsupported)
	}
	want := "^Bearer .*$"
	if m.NegateHeaderRegexp["Authorization"] != want {
		t.Errorf("negate_header_regexp: got %q, want %q", m.NegateHeaderRegexp["Authorization"], want)
	}
}

func TestMatcher_PositiveHeaderMatchesWithNotPath(t *testing.T) {
	// Positive header match combined with NOT-path exclusion
	node, err := condition.Parse(`(request.header.authorization Matches "Bearer *") AND !(proxy.pathsuffix MatchesPath "/health")`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	m := condition.ToCaddyMatcher(node)
	if len(m.Unsupported) != 0 {
		t.Errorf("unexpected unsupported: %v", m.Unsupported)
	}
	if len(m.ExcludePaths) != 1 || m.ExcludePaths[0] != "/health" {
		t.Errorf("exclude_paths: got %v", m.ExcludePaths)
	}
	if m.HeaderRegexp["Authorization"] != "^Bearer .*$" {
		t.Errorf("header_regexp: got %q", m.HeaderRegexp["Authorization"])
	}
}

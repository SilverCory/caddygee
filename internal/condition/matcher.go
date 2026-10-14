package condition

import (
	"strings"
)

// CaddyMatcher is the best-effort translation of an Apigee condition into
// Caddy named-matcher directives.
//
// Fields that remain nil/empty indicate no constraint for that dimension.
// Unsupported contains human-readable descriptions of sub-expressions that
// could not be translated — the emitter should output these as comments.
type CaddyMatcher struct {
	Methods        []string
	NegateMethods  bool     // when true, emit "not method <Methods...>" (block listed methods)
	Paths          []string
	ExcludePaths   []string          // paths to exclude via "not path" (from NOT path conditions)
	Headers        map[string]string // header name → required value
	HeadersPresent []string          // header names that must be present (not null check)
	HeaderRegexp        map[string]string // header name → regexp pattern (from Matches / StartsWith)
	NegateHeaderRegexp  map[string]string // header name → negated regexp pattern (from NOT Matches / NOT StartsWith)
	Unsupported         []string
}

// ToCaddyMatcher translates a parsed condition AST into a CaddyMatcher.
// A nil node returns an empty (match-all) matcher.
func ToCaddyMatcher(node Node) *CaddyMatcher {
	m := &CaddyMatcher{}
	if node == nil {
		return m
	}
	m.collect(node)
	return m
}

func (m *CaddyMatcher) collect(node Node) {
	switch n := node.(type) {
	case BinaryOp:
		if n.Op == "and" {
			m.collect(n.Left)
			m.collect(n.Right)
		} else {
			// "or" — if all branches are path comparisons, collect paths from
			// all branches (Caddy path matcher matches any listed path).
			// Otherwise mark as unsupported and include the left branch only.
			if allPathComparisons(n) {
				m.collectOrPaths(n)
			} else {
				m.Unsupported = append(m.Unsupported,
					"OR condition not directly translatable: use separate handle blocks")
				m.collect(n.Left) // best-effort: include left branch constraints
			}
		}

	case UnaryOp:
		// NOT (request.verb ~~ "^(GET|POST|OPTIONS)$") → not method GET POST OPTIONS
		if methods, ok := extractVerbRegexMethods(n); ok {
			m.appendNotMethods(methods)
			return
		}
		// NOT (proxy.pathsuffix MatchesPath "/docs/*") → not path /docs/*
		if paths, ok := extractNotPaths(n); ok {
			for _, p := range paths {
				m.ExcludePaths = appendUnique(m.ExcludePaths, p)
			}
			return
		}
		// NOT (request.header.Authorization Matches "Bearer *") → not header_regexp
		if hdrName, pattern, ok := extractNotHeader(n); ok {
			if m.NegateHeaderRegexp == nil {
				m.NegateHeaderRegexp = make(map[string]string)
			}
			m.NegateHeaderRegexp[hdrName] = pattern
			return
		}
		m.Unsupported = append(m.Unsupported,
			"NOT condition not directly translatable to a Caddy matcher")

	case Comparison:
		m.applyComparison(n)
	}
}

func (m *CaddyMatcher) applyComparison(c Comparison) {
	varName := strings.ToLower(c.Left)
	op := strings.ToLower(c.Op)

	if op == "==" {
		op = "="
	}

	switch varName {
	case "request.verb":
		if op == "=" {
			m.Methods = appendUnique(m.Methods, strings.ToUpper(c.Right))
		} else if op == "=|" || op == "startswith" {
			// Prefix match on verb — not translatable to a Caddy method matcher.
			m.Unsupported = append(m.Unsupported,
				"request.verb prefix match ("+c.Op+") is not translatable to a Caddy matcher")
		} else {
			m.Unsupported = append(m.Unsupported,
				"request.verb with operator "+c.Op+" is not translatable")
		}

	case "proxy.pathsuffix", "request.path":
		switch op {
		case "=":
			m.Paths = appendUnique(m.Paths, c.Right)
		case "matchespath", "matches":
			// Apigee MatchesPath uses ** glob; Caddy path matcher uses * and **
			m.Paths = appendUnique(m.Paths, apigeeGlobToCaddy(c.Right))
		case "javaregex", "~", "~/", "~~":
			m.Unsupported = append(m.Unsupported,
				"regex path matching ("+c.Op+") not translatable; use path_regexp in Caddy manually")
		case "=|", "startswith":
			// Prefix path match — convert to a glob pattern.
			m.Paths = appendUnique(m.Paths, apigeeGlobToCaddy(c.Right+"*"))
		default:
			m.Unsupported = append(m.Unsupported,
				varName+" with operator "+c.Op+" is not translatable")
		}

	default:
		// Header matching: request.header.<name>
		if strings.HasPrefix(varName, "request.header.") {
			headerName := canonicalHeader(c.Left[len("request.header."):])
			rightLower := strings.ToLower(c.Right)
			switch {
			case op == "=" && rightLower != "null":
				if m.Headers == nil {
					m.Headers = make(map[string]string)
				}
				m.Headers[headerName] = c.Right
			case op == "!=" && rightLower == "null":
				// "!= null" means the header must be present.
				m.HeadersPresent = appendUnique(m.HeadersPresent, headerName)
			case op == "=" && rightLower == "null":
				// "= null" (header absent) — not directly expressible; mark unsupported.
				m.Unsupported = append(m.Unsupported,
					"header "+headerName+" absent check (= null) is not translatable to a Caddy matcher")
			case op == "matches":
				// Apigee Matches uses glob-like patterns: "Bearer *" → regex "^Bearer .*$"
				if m.HeaderRegexp == nil {
					m.HeaderRegexp = make(map[string]string)
				}
				m.HeaderRegexp[headerName] = apigeeGlobToRegex(c.Right)
			case op == "=|" || op == "startswith":
				// Prefix match on header value → regex "^<value>"
				if m.HeaderRegexp == nil {
					m.HeaderRegexp = make(map[string]string)
				}
				m.HeaderRegexp[headerName] = "^" + regexEscapeLiteral(c.Right)
			case op == "javaregex" || op == "~" || op == "~/" || op == "~~":
				m.Unsupported = append(m.Unsupported,
					"header "+headerName+" with operator "+c.Op+" is not translatable to a Caddy matcher")
			default:
				m.Unsupported = append(m.Unsupported,
					"header "+headerName+" with operator "+c.Op+" is not translatable")
			}
			return
		}
		// environment.name is a runtime flow variable handled by when
		// at request time — silently drop it from the static matcher.
		if varName == "environment.name" {
			return
		}
		m.Unsupported = append(m.Unsupported,
			"variable "+c.Left+" is not translatable to a Caddy matcher")
	}
}

// extractNotPaths detects the pattern NOT (path comparison) or NOT (OR of path comparisons)
// and returns the list of paths to exclude. Returns (nil, false) if not this pattern.
func extractNotPaths(n UnaryOp) ([]string, bool) {
	if n.Op != "not" {
		return nil, false
	}
	// Single path comparison: NOT (proxy.pathsuffix MatchesPath "/docs/*")
	if cmp, ok := n.Operand.(Comparison); ok {
		v := strings.ToLower(cmp.Left)
		op := strings.ToLower(cmp.Op)
		if (v == "proxy.pathsuffix" || v == "request.path") &&
			(op == "matchespath" || op == "matches" || op == "=" || op == "=|" || op == "startswith") {
			var path string
			if op == "=|" || op == "startswith" {
				path = apigeeGlobToCaddy(cmp.Right + "*")
			} else {
				path = apigeeGlobToCaddy(cmp.Right)
			}
			return []string{path}, true
		}
		return nil, false
	}
	// OR of path comparisons: NOT (path1 OR path2 OR ...)
	if bin, ok := n.Operand.(BinaryOp); ok && allPathComparisons(bin) {
		var paths []string
		collectOrPathsFlat(bin, &paths)
		return paths, true
	}
	return nil, false
}

// collectOrPathsFlat walks an all-path OR tree and collects paths.
func collectOrPathsFlat(node Node, paths *[]string) {
	switch n := node.(type) {
	case BinaryOp:
		collectOrPathsFlat(n.Left, paths)
		collectOrPathsFlat(n.Right, paths)
	case Comparison:
		*paths = append(*paths, apigeeGlobToCaddy(n.Right))
	}
}

// extractNotHeader detects the pattern NOT (request.header.<name> Matches|=| "value")
// and returns (headerName, regexPattern, true). Returns ("", "", false) if not this pattern.
func extractNotHeader(n UnaryOp) (string, string, bool) {
	if n.Op != "not" {
		return "", "", false
	}
	cmp, ok := n.Operand.(Comparison)
	if !ok {
		return "", "", false
	}
	varName := strings.ToLower(cmp.Left)
	if !strings.HasPrefix(varName, "request.header.") {
		return "", "", false
	}
	headerName := canonicalHeader(cmp.Left[len("request.header."):])
	op := strings.ToLower(cmp.Op)
	switch op {
	case "matches":
		return headerName, apigeeGlobToRegex(cmp.Right), true
	case "=|", "startswith":
		return headerName, "^" + regexEscapeLiteral(cmp.Right), true
	}
	return "", "", false
}

// extractVerbRegexMethods detects the pattern NOT (request.verb ~~ "^(M1|M2)$")
// and returns the method list. Returns (nil, false) if not this pattern.
func extractVerbRegexMethods(n UnaryOp) ([]string, bool) {
	if n.Op != "not" {
		return nil, false
	}
	cmp, ok := n.Operand.(Comparison)
	if !ok {
		return nil, false
	}
	if strings.ToLower(cmp.Left) != "request.verb" {
		return nil, false
	}
	op := strings.ToLower(cmp.Op)
	if op != "~~" && op != "javaregex" && op != "~" && op != "~/" {
		return nil, false
	}
	// Parse methods from pattern like "^(GET|POST|OPTIONS)$"
	methods := parseRegexMethodList(cmp.Right)
	if len(methods) == 0 {
		return nil, false
	}
	return methods, true
}

// parseRegexMethodList extracts method names from a regex like "^(GET|POST|OPTIONS)$".
func parseRegexMethodList(pattern string) []string {
	// Strip surrounding quotes if present.
	p := strings.Trim(pattern, `"'`)
	// Expect pattern like ^(M1|M2|...)$
	p = strings.TrimPrefix(p, "^")
	p = strings.TrimSuffix(p, "$")
	p = strings.TrimPrefix(p, "(")
	p = strings.TrimSuffix(p, ")")
	if p == "" || strings.ContainsAny(p, ".*+?[]{}\\") {
		return nil
	}
	parts := strings.Split(p, "|")
	var methods []string
	for _, part := range parts {
		m := strings.TrimSpace(strings.ToUpper(part))
		if m != "" {
			methods = append(methods, m)
		}
	}
	return methods
}

// appendNotMethods sets NegateMethods and appends the given methods.
func (m *CaddyMatcher) appendNotMethods(methods []string) {
	m.NegateMethods = true
	for _, method := range methods {
		m.Methods = appendUnique(m.Methods, method)
	}
}

// allPathComparisons reports whether every leaf in an OR tree is a
// proxy.pathsuffix / request.path comparison with MatchesPath or "=".
func allPathComparisons(node Node) bool {
	switch n := node.(type) {
	case BinaryOp:
		if n.Op != "or" {
			return false
		}
		return allPathComparisons(n.Left) && allPathComparisons(n.Right)
	case Comparison:
		v := strings.ToLower(n.Left)
		op := strings.ToLower(n.Op)
		return (v == "proxy.pathsuffix" || v == "request.path") &&
			(op == "matchespath" || op == "matches" || op == "=")
	}
	return false
}

// collectOrPaths walks an all-path OR tree and appends every path to m.Paths.
func (m *CaddyMatcher) collectOrPaths(node Node) {
	switch n := node.(type) {
	case BinaryOp:
		m.collectOrPaths(n.Left)
		m.collectOrPaths(n.Right)
	case Comparison:
		m.Paths = appendUnique(m.Paths, apigeeGlobToCaddy(n.Right))
	}
}

// apigeeGlobToCaddy converts an Apigee MatchesPath glob to a Caddy path glob.
// Apigee uses ** for multi-segment wildcard (same as Caddy), * for single segment.
func apigeeGlobToCaddy(pattern string) string {
	return pattern
}

// canonicalHeader title-cases a header name, e.g. "x-api-key" → "X-Api-Key".
func canonicalHeader(s string) string {
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
		}
	}
	return strings.Join(parts, "-")
}

// apigeeGlobToRegex converts an Apigee glob pattern (used in Matches operator)
// to a regex pattern. Replaces * with .* and ? with . for matching.
// The result is anchored with ^ and $.
func apigeeGlobToRegex(pattern string) string {
	var b strings.Builder
	b.WriteByte('^')
	for _, ch := range pattern {
		switch ch {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		case '.', '+', '(', ')', '[', ']', '{', '}', '\\', '^', '$', '|':
			b.WriteByte('\\')
			b.WriteRune(ch)
		default:
			b.WriteRune(ch)
		}
	}
	b.WriteByte('$')
	return b.String()
}

// regexEscapeLiteral escapes regex metacharacters in a literal string.
func regexEscapeLiteral(s string) string {
	var b strings.Builder
	for _, ch := range s {
		switch ch {
		case '.', '*', '+', '?', '(', ')', '[', ']', '{', '}', '\\', '^', '$', '|':
			b.WriteByte('\\')
		}
		b.WriteRune(ch)
	}
	return b.String()
}

func appendUnique(slice []string, val string) []string {
	for _, v := range slice {
		if v == val {
			return slice
		}
	}
	return append(slice, val)
}

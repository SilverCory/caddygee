// Package condition parses Apigee condition expressions and translates them
// to Caddy matcher configurations.
//
// Apigee condition syntax (simplified BNF):
//
//	expr     = or_expr
//	or_expr  = and_expr ("or" and_expr)*
//	and_expr = unary_expr ("and" unary_expr)*
//	unary_expr = "not" unary_expr | "!" unary_expr | primary
//	primary  = "(" expr ")" | comparison
//	comparison = operand op operand
//	operand  = variable | string_literal | number_literal
//	op       = "=" | "!=" | ">" | "<" | ">=" | "<=" |
//	           "MatchesPath" | "Matches" | "JavaRegex" | "~" | "~/"
package condition

import (
	"fmt"
	"strings"
	"unicode"
)

// Node is a node in the condition AST.
type Node interface {
	nodeTag()
}

// BinaryOp represents "left op right" where op is "and" or "or".
type BinaryOp struct {
	Op    string // "and" | "or"
	Left  Node
	Right Node
}

func (BinaryOp) nodeTag() {}

// UnaryOp represents "not expr".
type UnaryOp struct {
	Op      string // "not"
	Operand Node
}

func (UnaryOp) nodeTag() {}

// Comparison represents "variable op value".
type Comparison struct {
	Left  string // variable name, e.g. "request.verb"
	Op    string // "=" | "!=" | "MatchesPath" | etc.
	Right string // string or number literal (unquoted)
}

func (Comparison) nodeTag() {}

// Parse parses an Apigee condition expression string into an AST.
// Returns an error if the expression is syntactically invalid.
func Parse(expr string) (Node, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}
	p := &parser{tokens: tokenize(expr)}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.tokens) {
		return nil, fmt.Errorf("unexpected token %q at position %d", p.tokens[p.pos], p.pos)
	}
	return node, nil
}

// ---- tokenizer ----

func tokenize(s string) []string {
	var tokens []string
	i := 0
	for i < len(s) {
		// skip whitespace
		if unicode.IsSpace(rune(s[i])) {
			i++
			continue
		}
		// quoted string
		if s[i] == '"' || s[i] == '\'' {
			quote := s[i]
			j := i + 1
			for j < len(s) && s[j] != quote {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			tokens = append(tokens, s[i:j+1])
			i = j + 1
			continue
		}
		// two-char operators
		if i+1 < len(s) {
			two := s[i : i+2]
			if two == "==" || two == "!=" || two == ">=" || two == "<=" || two == "~/" || two == "~~" || two == "=|" {
				tokens = append(tokens, two)
				i += 2
				continue
			}
		}
		// single-char operators / parens
		if strings.ContainsRune("=!><()", rune(s[i])) {
			tokens = append(tokens, string(s[i]))
			i++
			continue
		}
		// tilde (regex match shorthand)
		if s[i] == '~' {
			tokens = append(tokens, "~")
			i++
			continue
		}
		// word (variable, keyword, number)
		j := i
		for j < len(s) && !unicode.IsSpace(rune(s[j])) && !strings.ContainsRune("=!><()\"'~", rune(s[j])) {
			j++
		}
		if j > i {
			tokens = append(tokens, s[i:j])
			i = j
		} else {
			// unrecognised single char — include it and advance
			tokens = append(tokens, string(s[i]))
			i++
		}
	}
	return tokens
}

// ---- recursive-descent parser ----

type parser struct {
	tokens []string
	pos    int
}

func (p *parser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}

func (p *parser) consume() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "or") {
		p.consume()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = BinaryOp{Op: "or", Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "and") {
		p.consume()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = BinaryOp{Op: "and", Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (Node, error) {
	if strings.EqualFold(p.peek(), "not") || p.peek() == "!" {
		p.consume()
		operand, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return UnaryOp{Op: "not", Operand: operand}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Node, error) {
	if p.peek() == "(" {
		p.consume() // consume "("
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("expected ')', got %q", p.peek())
		}
		p.consume() // consume ")"
		return node, nil
	}
	return p.parseComparison()
}

// isOperator returns true if the token is a comparison operator.
func isOperator(t string) bool {
	switch strings.ToLower(t) {
	case "=", "==", "!=", ">", "<", ">=", "<=", "~", "~/", "~~", "=|",
		"matchespath", "matches", "javaregex", "startswith":
		return true
	}
	return false
}

func (p *parser) parseComparison() (Node, error) {
	left := p.consume()
	if left == "" {
		return nil, fmt.Errorf("unexpected end of expression")
	}
	op := p.peek()
	if !isOperator(op) {
		// Boolean variable reference (e.g. "request.header.exists")
		return Comparison{Left: left, Op: "=", Right: "true"}, nil
	}
	p.consume() // consume operator
	right := p.consume()
	if right == "" {
		return nil, fmt.Errorf("expected right-hand operand after %q", op)
	}
	// Strip surrounding quotes from string literals.
	if len(right) >= 2 && (right[0] == '"' || right[0] == '\'') {
		right = right[1 : len(right)-1]
	}
	return Comparison{Left: left, Op: op, Right: right}, nil
}

package apigeecompat_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"caddygee/modules/apigeecompat"
)

// newRequestWithFS returns a new request with an active FlowState already seeded
// with the provided key-value pairs. Convenience helper for condition tests.
func newRequestWithFS(t *testing.T, method, path string, vars map[string]string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)

	// We need flow state in the request context. Use FlowStateManager to create it,
	// then capture and modify it.
	var capturedReq *http.Request
	mgr := apigeecompat.FlowStateManager{}
	next := makeCapturingHandler(func(r *http.Request) {
		capturedReq = r
		fs, _ := apigeecompat.GetFlowState(r.Context())
		for k, v := range vars {
			fs.Set(k, v)
		}
	})
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)
	if capturedReq == nil {
		t.Fatal("FlowStateManager did not call next")
	}
	return capturedReq
}

// ---------------------------------------------------------------------------
// evalCondition white-box tests via EvalCondition export
// ---------------------------------------------------------------------------

func TestEvalCondition_Empty_ReturnsTrue(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if !apigeecompat.EvalCondition("", req, nil) {
		t.Error("empty condition should return true")
	}
}

func TestEvalCondition_RequestVerb_Match(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if !apigeecompat.EvalCondition(`request.verb = "POST"`, req, nil) {
		t.Error("expected true for POST verb match")
	}
}

func TestEvalCondition_RequestVerb_NoMatch(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if apigeecompat.EvalCondition(`request.verb = "POST"`, req, nil) {
		t.Error("expected false for GET verb vs POST match")
	}
}

func TestEvalCondition_ProxyPathsuffix_Match(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	if !apigeecompat.EvalCondition(`proxy.pathsuffix = "/api/users"`, req, nil) {
		t.Error("expected true for path match")
	}
}

func TestEvalCondition_EnvironmentName_FromFlowVar(t *testing.T) {
	req := newRequestWithFS(t, http.MethodGet, "/", map[string]string{
		"environment.name": "prod",
	})
	fs, _ := apigeecompat.GetFlowState(req.Context())
	if !apigeecompat.EvalCondition(`environment.name = "prod"`, req, fs) {
		t.Error("expected true for environment.name=prod")
	}
}

func TestEvalCondition_EnvironmentName_NoMatch(t *testing.T) {
	req := newRequestWithFS(t, http.MethodGet, "/", map[string]string{
		"environment.name": "preview",
	})
	fs, _ := apigeecompat.GetFlowState(req.Context())
	if apigeecompat.EvalCondition(`environment.name = "prod"`, req, fs) {
		t.Error("expected false when environment.name=preview vs prod")
	}
}

func TestEvalCondition_AND_BothTrue(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	if !apigeecompat.EvalCondition(`request.verb = "POST" AND proxy.pathsuffix = "/submit"`, req, nil) {
		t.Error("expected true for AND with both conditions true")
	}
}

func TestEvalCondition_AND_OneFalse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/submit", nil)
	if apigeecompat.EvalCondition(`request.verb = "POST" AND proxy.pathsuffix = "/submit"`, req, nil) {
		t.Error("expected false for AND when verb is GET not POST")
	}
}

func TestEvalCondition_OR_OneTrue(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Verb is GET (first is false), but path "/" matches second.
	if !apigeecompat.EvalCondition(`request.verb = "POST" OR proxy.pathsuffix = "/"`, req, nil) {
		t.Error("expected true for OR when second clause is true")
	}
}

func TestEvalCondition_OR_BothFalse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	if apigeecompat.EvalCondition(`request.verb = "POST" OR proxy.pathsuffix = "/"`, req, nil) {
		t.Error("expected false for OR when both clauses are false")
	}
}

func TestEvalCondition_NOT_Negates(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if !apigeecompat.EvalCondition(`NOT request.verb = "POST"`, req, nil) {
		t.Error("expected true: NOT(POST) when verb is GET")
	}
}

func TestEvalCondition_NOT_Bang_Negates(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if !apigeecompat.EvalCondition(`!request.verb = "POST"`, req, nil) {
		t.Error("expected true: !(POST) when verb is GET")
	}
}

func TestEvalCondition_Parens_Grouping(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/a", nil)
	// (GET AND /a) OR (POST AND /b) — first group is true.
	cond := `(request.verb = "GET" AND proxy.pathsuffix = "/a") OR (request.verb = "POST" AND proxy.pathsuffix = "/b")`
	if !apigeecompat.EvalCondition(cond, req, nil) {
		t.Error("expected true: first paren group matches")
	}
}

func TestEvalCondition_MatchesPath_Wildcard(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/users/123", nil)
	if !apigeecompat.EvalCondition(`proxy.pathsuffix MatchesPath "/api/users/*"`, req, nil) {
		t.Error("expected true for MatchesPath wildcard")
	}
}

func TestEvalCondition_MatchesPath_NoMatch(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/other/path", nil)
	if apigeecompat.EvalCondition(`proxy.pathsuffix MatchesPath "/api/users/*"`, req, nil) {
		t.Error("expected false for MatchesPath when path differs")
	}
}

func TestEvalCondition_NullCheck_Equals(t *testing.T) {
	// A flow var that is not set should equal "null".
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No flow state — fs is nil; resolveVar returns "".
	if !apigeecompat.EvalCondition(`environment.name = null`, req, nil) {
		t.Error("expected true: unset var equals null")
	}
}

func TestEvalCondition_NullCheck_NotEquals(t *testing.T) {
	req := newRequestWithFS(t, http.MethodGet, "/", map[string]string{
		"environment.name": "prod",
	})
	fs, _ := apigeecompat.GetFlowState(req.Context())
	if apigeecompat.EvalCondition(`environment.name = null`, req, fs) {
		t.Error("expected false: set var should not equal null")
	}
}

func TestEvalCondition_NotEquals_Op(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if !apigeecompat.EvalCondition(`request.verb != "POST"`, req, nil) {
		t.Error("expected true: GET != POST")
	}
}

func TestEvalCondition_RequestHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Custom", "myvalue")
	if !apigeecompat.EvalCondition(`request.header.X-Custom = "myvalue"`, req, nil) {
		t.Error("expected true for request.header match")
	}
}

func TestEvalCondition_NilFlowState_NoOp(t *testing.T) {
	// When fs is nil, flow variable lookups should return "" without panicking.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// This must not panic:
	result := apigeecompat.EvalCondition(`environment.name = "prod"`, req, nil)
	if result {
		t.Error("expected false: nil fs means environment.name resolves to empty")
	}
}

func TestEvalCondition_BooleanFlowVar_True(t *testing.T) {
	req := newRequestWithFS(t, http.MethodGet, "/", map[string]string{
		"isValid": "true",
	})
	fs, _ := apigeecompat.GetFlowState(req.Context())
	if !apigeecompat.EvalCondition(`isValid`, req, fs) {
		t.Error("expected true: boolean flow var 'isValid'='true'")
	}
}

func TestEvalCondition_BooleanFlowVar_False(t *testing.T) {
	req := newRequestWithFS(t, http.MethodGet, "/", map[string]string{
		"isValid": "false",
	})
	fs, _ := apigeecompat.GetFlowState(req.Context())
	if apigeecompat.EvalCondition(`isValid`, req, fs) {
		t.Error("expected false: boolean flow var 'isValid'='false'")
	}
}

func TestEvalCondition_StartsWith(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v2/resource", nil)
	if !apigeecompat.EvalCondition(`proxy.pathsuffix StartsWith "/api/"`, req, nil) {
		t.Error("expected true: path starts with /api/")
	}
}

func TestEvalCondition_StartsWith_NoMatch(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/other/path", nil)
	if apigeecompat.EvalCondition(`proxy.pathsuffix StartsWith "/api/"`, req, nil) {
		t.Error("expected false: path does not start with /api/")
	}
}

func TestEvalCondition_NumericComparison_Greater(t *testing.T) {
	req := newRequestWithFS(t, http.MethodGet, "/", map[string]string{
		"count": "5",
	})
	fs, _ := apigeecompat.GetFlowState(req.Context())
	if !apigeecompat.EvalCondition(`count > 3`, req, fs) {
		t.Error("expected true: 5 > 3")
	}
}

func TestEvalCondition_NumericComparison_Less(t *testing.T) {
	req := newRequestWithFS(t, http.MethodGet, "/", map[string]string{
		"count": "2",
	})
	fs, _ := apigeecompat.GetFlowState(req.Context())
	// 2 > 3 is false.
	if apigeecompat.EvalCondition(`count > 3`, req, fs) {
		t.Error("expected false: 2 > 3")
	}
}

// ---------------------------------------------------------------------------
// GlobMatch / MatchesPath edge cases
// ---------------------------------------------------------------------------

func TestEvalCondition_MatchesPath_DoubleWildcard(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v2/deeply/nested/path", nil)
	// ** should match any path
	if !apigeecompat.EvalCondition(`proxy.pathsuffix MatchesPath "**"`, req, nil) {
		t.Error("expected true: ** matches any path")
	}
}

func TestEvalCondition_Matches_Alias(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/users/42", nil)
	if !apigeecompat.EvalCondition(`proxy.pathsuffix Matches "/users/*"`, req, nil) {
		t.Error("expected true: Matches is alias for MatchesPath")
	}
}

// ---------------------------------------------------------------------------
// Complex compound expressions
// ---------------------------------------------------------------------------

func TestEvalCondition_AndOr_Precedence(t *testing.T) {
	// AND has higher precedence than OR.
	// "false AND false OR true" → (false AND false) OR true → false OR true → true
	req := newRequestWithFS(t, http.MethodPost, "/other", map[string]string{
		"environment.name": "prod",
	})
	fs, _ := apigeecompat.GetFlowState(req.Context())
	// request.verb="POST" AND proxy.pathsuffix="/x" → false (path mismatch)
	// OR environment.name="prod" → true
	cond := `request.verb = "POST" AND proxy.pathsuffix = "/x" OR environment.name = "prod"`
	if !apigeecompat.EvalCondition(cond, req, fs) {
		t.Error("expected true: OR of (false AND) with true env.name check")
	}
}

func TestEvalCondition_TripleNot(t *testing.T) {
	// NOT NOT NOT false = NOT NOT true = NOT false = true... wait: NOT(NOT(NOT(false))) = NOT(NOT(true)) = NOT(false) = true
	// Actually NOT NOT x = x so triple NOT: = NOT x which for false → true
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	// request.verb="GET" is false
	if !apigeecompat.EvalCondition(`NOT NOT NOT request.verb = "GET"`, req, nil) {
		t.Error("expected true: NOT NOT NOT false = true")
	}
}

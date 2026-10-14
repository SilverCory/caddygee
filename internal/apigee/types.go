package apigee

// Bundle is the fully parsed and cross-referenced result of an Apigee API proxy bundle.
type Bundle struct {
	// Dir is the resolved apiproxy/ directory path; used to load resource files.
	Dir             string
	ProxyEndpoints  []ProxyEndpoint
	TargetEndpoints []TargetEndpoint
	Policies        map[string]Policy
}

// APIProxy is the root descriptor found in apiproxy/*.xml.
type APIProxy struct {
	Name             string   `xml:"name,attr"`
	DisplayName      string   `xml:"DisplayName"`
	ProxyEndpoints   []string `xml:"ProxyEndpoints>ProxyEndpoint"`
	TargetEndpoints  []string `xml:"TargetEndpoints>TargetEndpoint"`
}

// ProxyEndpoint is parsed from apiproxy/proxies/*.xml.
type ProxyEndpoint struct {
	Name                string              `xml:"name,attr"`
	HTTPProxyConnection HTTPProxyConnection `xml:"HTTPProxyConnection"`
	PreFlow             PreFlow             `xml:"PreFlow"`
	PostFlow            PostFlow            `xml:"PostFlow"`
	Flows               []Flow              `xml:"Flows>Flow"`
	RouteRules          []RouteRule         `xml:"RouteRule"`
}

// RouteRule selects a TargetEndpoint based on an optional condition.
type RouteRule struct {
	Name           string `xml:"name,attr"`
	Condition      string `xml:"Condition"`
	TargetEndpoint string `xml:"TargetEndpoint"`
}

// HTTPProxyConnection holds the inbound connection config for a ProxyEndpoint.
type HTTPProxyConnection struct {
	BasePath   string `xml:"BasePath"`
	VirtualHost string `xml:"VirtualHost"`
}

// TargetEndpoint is parsed from apiproxy/targets/*.xml.
type TargetEndpoint struct {
	Name                 string               `xml:"name,attr"`
	HTTPTargetConnection HTTPTargetConnection `xml:"HTTPTargetConnection"`
	PreFlow              PreFlow              `xml:"PreFlow"`
	PostFlow             PostFlow             `xml:"PostFlow"`
	Flows                []Flow               `xml:"Flows>Flow"`
}

// HTTPTargetConnection holds the upstream target URL.
type HTTPTargetConnection struct {
	URL            string          `xml:"URL"`
	LoadBalancer   *LoadBalancer   `xml:"LoadBalancer"`
	SSLInfo        *SSLInfo        `xml:"SSLInfo"`
	Authentication *Authentication `xml:"Authentication"`
}

// Authentication holds outbound auth config for a TargetEndpoint.
type Authentication struct {
	GoogleIDToken *GoogleIDToken `xml:"GoogleIDToken"`
}

// GoogleIDToken requests a Google OIDC ID Token for the given audience,
// injected as the Authorization header on outbound requests.
type GoogleIDToken struct {
	Audience string `xml:"Audience"`
}

// LoadBalancer lists named TargetServers for load balancing.
type LoadBalancer struct {
	Servers []TargetServer `xml:"Server"`
}

// TargetServer is a named backend server reference.
type TargetServer struct {
	Name string `xml:"name,attr"`
}

// SSLInfo carries TLS configuration for a target connection.
type SSLInfo struct {
	Enabled  bool `xml:"Enabled"`
	ClientAuthEnabled bool `xml:"ClientAuthEnabled"`
}

// Flow represents a conditional named flow (request + response steps).
type Flow struct {
	Name      string    `xml:"name,attr"`
	Condition string    `xml:"Condition"`
	Request   StepList  `xml:"Request"`
	Response  StepList  `xml:"Response"`
}

// StepList is a list of policy execution steps within a flow phase.
type StepList struct {
	Steps []Step `xml:"Step"`
}

// Step references a policy by name with an optional condition.
type Step struct {
	Name      string `xml:"Name"`
	Condition string `xml:"Condition"`
}

// PreFlow holds request and response steps that always run before named flows.
type PreFlow struct {
	Name     string   `xml:"name,attr"`
	Request  StepList `xml:"Request"`
	Response StepList `xml:"Response"`
}

// PostFlow holds request and response steps that always run after named flows.
type PostFlow struct {
	Name     string   `xml:"name,attr"`
	Request  StepList `xml:"Request"`
	Response StepList `xml:"Response"`
}

// Policy is the parsed definition from apiproxy/policies/*.xml.
// The Type field is the XML element name (e.g. "AssignMessage", "ServiceCallout").
type Policy struct {
	Name        string `xml:"name,attr"`
	DisplayName string `xml:"DisplayName"`
	Type        string // set by the parser from the XML element name

	// AssignMessage fields
	AssignMessage *AssignMessage

	// ServiceCallout fields
	ServiceCallout *ServiceCallout

	// JavaScriptCallout fields
	JavaScriptCallout *JavaScriptCallout

	// RaiseFault fields
	RaiseFault *RaiseFault

	// VerifyJWT fields
	VerifyJWT *VerifyJWT

	// SpikeArrest fields
	SpikeArrest *SpikeArrestPolicy

	// CORS fields
	CORS *CORSPolicy

	// VerifyAPIKey fields
	VerifyAPIKey *VerifyAPIKeyPolicy
}

// AssignMessage holds parsed config for an <AssignMessage> policy.
type AssignMessage struct {
	AssignTo        AssignTo         `xml:"AssignTo"`
	Set             MessageMutation  `xml:"Set"`
	Add             MessageMutation  `xml:"Add"`
	Remove          MessageRemove    `xml:"Remove"`
	AssignVariable  []AssignVariable `xml:"AssignVariable"`
}

// AssignTo describes whether the policy targets the request or response.
type AssignTo struct {
	Type       string `xml:"type,attr"` // "request" or "response"
	CreateNew  bool   `xml:"createNew,attr"`
}

// MessageMutation holds headers and body to set or add.
type MessageMutation struct {
	Headers []Header `xml:"Headers>Header"`
	Body    string   `xml:"Payload"`
}

// MessageRemove holds headers and query params to remove.
type MessageRemove struct {
	Headers []Header `xml:"Headers>Header"`
}

// Header is a name/value pair.
type Header struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// AssignVariable sets a flow variable from a value or ref.
type AssignVariable struct {
	Name  string `xml:"Name"`
	Value string `xml:"Value"`
	Ref   string `xml:"Ref"`
}

// ServiceCallout holds parsed config for a <ServiceCallout> policy.
type ServiceCallout struct {
	Name           string         `xml:"name,attr"`
	DisplayName    string         `xml:"DisplayName"`
	Request        CalloutRequest `xml:"Request"`
	Response       string         `xml:"Response"` // variable name to store response
	HTTPTargetConnection HTTPTargetConnection `xml:"HTTPTargetConnection"`
}

// CalloutRequest describes the outbound request in a ServiceCallout.
type CalloutRequest struct {
	Variable string   `xml:"variable,attr"`
	Headers  []Header `xml:"Set>Headers>Header"`
}

// RaiseFault holds parsed config for a <RaiseFault> policy.
type RaiseFault struct {
	FaultResponse FaultResponse `xml:"FaultResponse"`
}

// FaultResponse describes the HTTP response to return.
type FaultResponse struct {
	Set FaultResponseSet `xml:"Set"`
}

// FaultResponseSet holds the status code, reason phrase, and payload.
type FaultResponseSet struct {
	StatusCode   int    `xml:"StatusCode"`
	ReasonPhrase string `xml:"ReasonPhrase"`
	Payload      string `xml:"Payload"`
}

// VerifyJWT holds parsed config for a <VerifyJWT> policy.
type VerifyJWT struct {
	Algorithm string        `xml:"Algorithm"`
	PublicKey VerifyJWTKey  `xml:"PublicKey"`
	Issuer    string        `xml:"Issuer"`
	Audience  string        `xml:"Audience"`
}

// VerifyJWTKey holds either a static PEM value or a JWKS URI.
type VerifyJWTKey struct {
	Value string `xml:"Value"`
	JWKS  JWKS   `xml:"JWKS"`
}

// JWKS holds the JWKS URI for dynamic key fetching.
type JWKS struct {
	URI string `xml:"uri,attr"`
}

// JavaScriptCallout holds parsed config for a <Javascript> policy.
type JavaScriptCallout struct {
	// ResourceURL references an external JS file (e.g. "jsc://my-script.js").
	// Only inline Source is supported by the apigee_javascript_callout module;
	// a ResourceURL-only policy will be emitted as an unsupported handler.
	ResourceURL string `xml:"ResourceURL"`
	// Source is the inline JavaScript source code.
	Source string `xml:"Source"`
	// TimeLimit is the maximum execution time in milliseconds (default 200).
	TimeLimit int `xml:"timeLimit,attr"`
}

// SpikeArrestPolicy holds parsed config for a <SpikeArrest> policy.
type SpikeArrestPolicy struct {
	Rate string `xml:"Rate"` // e.g. "30ps" (per second) or "10pm" (per minute)
}

// CORSPolicy holds parsed config for a <CORS> policy.
type CORSPolicy struct {
	AllowOrigins              string `xml:"AllowOrigins"`
	AllowMethods              string `xml:"AllowMethods"`
	AllowHeaders              string `xml:"AllowHeaders"`
	ExposeHeaders             string `xml:"ExposeHeaders"`
	MaxAge                    int    `xml:"MaxAge"`
	AllowCredentials          string `xml:"AllowCredentials"`
	GeneratePreflightResponse bool   `xml:"GeneratePreflightResponse"`
}

// VerifyAPIKeyPolicy holds parsed config for a <VerifyAPIKey> policy.
type VerifyAPIKeyPolicy struct {
	APIKey VerifyAPIKeyRef `xml:"APIKey"`
}

// VerifyAPIKeyRef holds the ref attribute for the API key source.
type VerifyAPIKeyRef struct {
	Ref string `xml:"ref,attr"`
}

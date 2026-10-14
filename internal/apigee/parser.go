package apigee

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ParseBundle reads an Apigee API proxy bundle directory and returns a fully
// cross-referenced Bundle. The dir argument should point to the apiproxy/
// directory (or its parent — both layouts are accepted).
func ParseBundle(dir string) (*Bundle, error) {
	// Accept either the parent dir or the apiproxy/ dir itself.
	if _, err := os.Stat(filepath.Join(dir, "apiproxy")); err == nil {
		dir = filepath.Join(dir, "apiproxy")
	}

	// Validate that the resolved directory exists.
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("bundle directory does not exist: %s", dir)
	}

	bundle := &Bundle{
		Dir:      dir,
		Policies: make(map[string]Policy),
	}

	if err := parsePolicies(filepath.Join(dir, "policies"), bundle); err != nil {
		return nil, fmt.Errorf("parsing policies: %w", err)
	}
	if err := parseProxyEndpoints(filepath.Join(dir, "proxies"), bundle); err != nil {
		return nil, fmt.Errorf("parsing proxy endpoints: %w", err)
	}
	if err := parseTargetEndpoints(filepath.Join(dir, "targets"), bundle); err != nil {
		return nil, fmt.Errorf("parsing target endpoints: %w", err)
	}

	return bundle, nil
}

func parsePolicies(dir string, bundle *Bundle) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil // policies directory is optional
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".xml") {
			continue
		}
		p, err := parsePolicyFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("file %s: %w", e.Name(), err)
		}
		bundle.Policies[p.Name] = p
	}
	return nil
}

func parsePolicyFile(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}

	// Decode the outer element to get the type (element name) and name attribute.
	// Skip over processing instructions, comments, and whitespace to find the first start element.
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	var startElem xml.StartElement
	for {
		tok, err := dec.Token()
		if err != nil {
			return Policy{}, fmt.Errorf("reading token: %w", err)
		}
		var ok bool
		startElem, ok = tok.(xml.StartElement)
		if ok {
			break
		}
	}

	policyType := startElem.Name.Local
	var nameAttr string
	for _, a := range startElem.Attr {
		if a.Name.Local == "name" {
			nameAttr = a.Value
		}
	}

	p := Policy{
		Name: nameAttr,
		Type: policyType,
	}

	switch policyType {
	case "AssignMessage":
		var am AssignMessage
		if err := xml.Unmarshal(data, &am); err != nil {
			return Policy{}, fmt.Errorf("unmarshal AssignMessage: %w", err)
		}
		p.AssignMessage = &am
	case "ServiceCallout":
		var sc ServiceCallout
		if err := xml.Unmarshal(data, &sc); err != nil {
			return Policy{}, fmt.Errorf("unmarshal ServiceCallout: %w", err)
		}
		p.ServiceCallout = &sc
	case "Javascript":
		var jsc JavaScriptCallout
		if err := xml.Unmarshal(data, &jsc); err != nil {
			return Policy{}, fmt.Errorf("unmarshal Javascript: %w", err)
		}
		p.JavaScriptCallout = &jsc
	case "RaiseFault":
		var rf RaiseFault
		if err := xml.Unmarshal(data, &rf); err != nil {
			return Policy{}, fmt.Errorf("unmarshal RaiseFault: %w", err)
		}
		p.RaiseFault = &rf
	case "VerifyJWT":
		var vj VerifyJWT
		if err := xml.Unmarshal(data, &vj); err != nil {
			return Policy{}, fmt.Errorf("unmarshal VerifyJWT: %w", err)
		}
		p.VerifyJWT = &vj
	case "SpikeArrest":
		var sa SpikeArrestPolicy
		if err := xml.Unmarshal(data, &sa); err != nil {
			return Policy{}, fmt.Errorf("unmarshal SpikeArrest: %w", err)
		}
		p.SpikeArrest = &sa
	case "CORS":
		var cors CORSPolicy
		if err := xml.Unmarshal(data, &cors); err != nil {
			return Policy{}, fmt.Errorf("unmarshal CORS: %w", err)
		}
		p.CORS = &cors
	case "VerifyAPIKey":
		var vak VerifyAPIKeyPolicy
		if err := xml.Unmarshal(data, &vak); err != nil {
			return Policy{}, fmt.Errorf("unmarshal VerifyAPIKey: %w", err)
		}
		p.VerifyAPIKey = &vak
	case "ExtractVariables":
		var ev ExtractVariablesPolicy
		if err := xml.Unmarshal(data, &ev); err != nil {
			return Policy{}, fmt.Errorf("unmarshal ExtractVariables: %w", err)
		}
		p.ExtractVariables = &ev
	case "Quota":
		var q QuotaPolicy
		if err := xml.Unmarshal(data, &q); err != nil {
			return Policy{}, fmt.Errorf("unmarshal Quota: %w", err)
		}
		p.Quota = &q
	case "KeyValueMapOperations":
		var kvm KVMPolicy
		if err := xml.Unmarshal(data, &kvm); err != nil {
			return Policy{}, fmt.Errorf("unmarshal KeyValueMapOperations: %w", err)
		}
		p.KVM = &kvm
	default:
		// Unknown policy types are stored with type only — no parsed config.
		// The transpiler will emit a comment for unsupported types.
	}

	// Fall back to filename stem as name if the attribute was absent.
	if p.Name == "" {
		base := filepath.Base(path)
		p.Name = strings.TrimSuffix(base, ".xml")
	}

	return p, nil
}

func parseProxyEndpoints(dir string, bundle *Bundle) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".xml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		var ep ProxyEndpoint
		if err := xml.Unmarshal(data, &ep); err != nil {
			return fmt.Errorf("file %s: %w", e.Name(), err)
		}
		bundle.ProxyEndpoints = append(bundle.ProxyEndpoints, ep)
	}
	return nil
}

func parseTargetEndpoints(dir string, bundle *Bundle) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".xml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		var ep TargetEndpoint
		if err := xml.Unmarshal(data, &ep); err != nil {
			return fmt.Errorf("file %s: %w", e.Name(), err)
		}
		bundle.TargetEndpoints = append(bundle.TargetEndpoints, ep)
	}
	return nil
}

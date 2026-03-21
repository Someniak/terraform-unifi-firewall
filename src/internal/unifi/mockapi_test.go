package unifi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// mockUnifiAPI is a stateful mock of the UniFi Network API for testing.
// It stores resources in memory and supports CRUD operations, error injection,
// and call counting.
type mockUnifiAPI struct {
	mu sync.Mutex

	sites      []Site
	zones      map[string][]FirewallZone   // keyed by siteID
	networks   map[string][]Network        // keyed by siteID
	fwPolicies  map[string][]FirewallPolicy // keyed by siteID
	dnsPolicies map[string][]DNSPolicy      // keyed by siteID
	clients     map[string][]ClientDevice   // keyed by siteID
	aclRules    map[string][]ACLRule        // keyed by siteID
	trafficLists map[string][]TrafficMatchingList // keyed by siteID

	// fwPolicyOrdering stores the policy ordering per siteID
	fwPolicyOrdering map[string][]string
	// aclRuleOrdering stores the ACL rule ordering per siteID
	aclRuleOrdering map[string][]string

	nextID int

	// callCounts tracks how many times each "METHOD /path" was hit.
	callCounts map[string]*atomic.Int32

	// errorOverrides forces a specific HTTP status for matching "METHOD /path-prefix".
	errorOverrides map[string]int
}

// newMockServer creates a mock API with sensible defaults and returns the
// httptest.Server and the mock for test assertions.
func newMockServer(t *testing.T) (*httptest.Server, *mockUnifiAPI) {
	t.Helper()
	m := &mockUnifiAPI{
		sites: []Site{
			{ID: "site-1", Name: "Default", InternalReference: "default"},
		},
		zones: map[string][]FirewallZone{
			"site-1": {
				{ID: "zone-lan", Name: "LAN", NetworkIDs: []string{"net-1"}},
				{ID: "zone-wan", Name: "WAN", NetworkIDs: []string{"net-2"}},
			},
		},
		networks: map[string][]Network{
			"site-1": {
				{ID: "net-1", Name: "Default", VlanID: 1, Management: "GATEWAY"},
				{ID: "net-2", Name: "Guest", VlanID: 100, Management: "GATEWAY"},
			},
		},
		fwPolicies:  map[string][]FirewallPolicy{},
		dnsPolicies: map[string][]DNSPolicy{},
		aclRules:    map[string][]ACLRule{},
		trafficLists: map[string][]TrafficMatchingList{},
		fwPolicyOrdering: map[string][]string{},
		aclRuleOrdering: map[string][]string{},
		clients: map[string][]ClientDevice{
			"site-1": {
				{ID: "client-1", MAC: "00:11:22:33:44:55", Name: "server1"},
				{ID: "client-2", MAC: "aa:bb:cc:dd:ee:ff", Name: "laptop1"},
			},
		},
		callCounts:     map[string]*atomic.Int32{},
		errorOverrides: map[string]int{},
		nextID:         100,
	}

	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return srv, m
}

func (m *mockUnifiAPI) genID() string {
	m.nextID++
	return fmt.Sprintf("mock-%d", m.nextID)
}

func (m *mockUnifiAPI) trackCall(method, path string) {
	key := method + " " + path
	m.mu.Lock()
	if _, ok := m.callCounts[key]; !ok {
		m.callCounts[key] = &atomic.Int32{}
	}
	counter := m.callCounts[key]
	m.mu.Unlock()
	counter.Add(1)
}

// GetCallCount returns the number of times a specific "METHOD /path" was called.
func (m *mockUnifiAPI) GetCallCount(method, path string) int32 {
	key := method + " " + path
	m.mu.Lock()
	counter, ok := m.callCounts[key]
	m.mu.Unlock()
	if !ok {
		return 0
	}
	return counter.Load()
}

// SetError injects an error response for any request matching "METHOD /path-prefix".
func (m *mockUnifiAPI) SetError(method, pathPrefix string, statusCode int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorOverrides[method+" "+pathPrefix] = statusCode
}

// ClearError removes an error override.
func (m *mockUnifiAPI) ClearError(method, pathPrefix string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.errorOverrides, method+" "+pathPrefix)
}

// SetMalformedResponse makes the mock return invalid JSON for matching requests.
// Uses status 200 with garbage body to test unmarshal error paths.
func (m *mockUnifiAPI) SetMalformedResponse(method, pathPrefix string) {
	// We use a special status code 999 as a sentinel for malformed response.
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorOverrides[method+" "+pathPrefix] = 999
}

func (m *mockUnifiAPI) checkError(method, path string, w http.ResponseWriter) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, code := range m.errorOverrides {
		parts := strings.SplitN(key, " ", 2)
		if len(parts) == 2 && parts[0] == method && strings.HasPrefix(path, parts[1]) {
			if code == 999 {
				// Malformed response
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("not valid json{{{"))
				return true
			}
			w.WriteHeader(code)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("mock error %d", code)})
			return true
		}
	}
	return false
}

func (m *mockUnifiAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method
	m.trackCall(method, path)

	w.Header().Set("Content-Type", "application/json")

	if m.checkError(method, path, w) {
		return
	}

	// Route: POST /api/login (legacy cookie auth)
	if path == "/api/login" && method == http.MethodPost {
		body, _ := io.ReadAll(r.Body)
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		json.Unmarshal(body, &creds)
		if creds.Username == "admin" && creds.Password == "password" {
			http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "mock-session-token", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "mock-csrf-token", Path: "/"})
			w.Header().Set("X-CSRF-Token", "mock-csrf-token")
			json.NewEncoder(w).Encode(map[string]interface{}{"meta": map[string]string{"rc": "ok"}, "data": []interface{}{}})
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
		}
		return
	}

	// Route: REST API /api/s/{site}/rest/user (legacy client CRUD)
	if strings.HasPrefix(path, "/api/s/") {
		restParts := strings.Split(strings.TrimPrefix(path, "/api/s/"), "/")
		// /api/s/{siteRef}/rest/user or /api/s/{siteRef}/rest/user/{id}
		if len(restParts) >= 3 && restParts[1] == "rest" && restParts[2] == "user" {
			// Map siteRef to siteID (for mock, "default" -> "site-1")
			siteID := "site-1"
			if len(restParts) == 3 {
				// Collection
				m.handleRestClients(w, r, siteID)
			} else {
				// Single item
				m.handleRestClient(w, r, siteID, restParts[3])
			}
			return
		}
	}

	// Route: GET /v1/sites
	if path == "/v1/sites" && method == http.MethodGet {
		m.mu.Lock()
		sites := m.sites
		m.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{"data": sites})
		return
	}

	// Parse /v1/sites/{siteId}/...
	parts := strings.Split(strings.TrimPrefix(path, "/v1/sites/"), "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	siteID := parts[0]

	// Route: firewall zones collection
	if len(parts) == 3 && parts[1] == "firewall" && parts[2] == "zones" {
		m.handleFirewallZones(w, r, siteID)
		return
	}

	// Route: firewall zones single item
	if len(parts) == 4 && parts[1] == "firewall" && parts[2] == "zones" {
		m.handleFirewallZone(w, r, siteID, parts[3])
		return
	}

	// Route: networks
	if len(parts) == 2 && parts[1] == "networks" && method == http.MethodGet {
		m.mu.Lock()
		networks := m.networks[siteID]
		m.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{"data": networks})
		return
	}

	// Route: firewall policy ordering
	if len(parts) == 4 && parts[1] == "firewall" && parts[2] == "policies" && parts[3] == "ordering" {
		m.handleFWPolicyOrdering(w, r, siteID)
		return
	}

	// Route: firewall policies collection
	if len(parts) == 3 && parts[1] == "firewall" && parts[2] == "policies" {
		m.handleFWPolicies(w, r, siteID)
		return
	}

	// Route: firewall policies single item
	if len(parts) == 4 && parts[1] == "firewall" && parts[2] == "policies" {
		m.handleFWPolicy(w, r, siteID, parts[3])
		return
	}

	// Route: DNS policies collection
	if len(parts) == 3 && parts[1] == "dns" && parts[2] == "policies" {
		m.handleDNSPolicies(w, r, siteID)
		return
	}

	// Route: DNS policies single item
	if len(parts) == 4 && parts[1] == "dns" && parts[2] == "policies" {
		m.handleDNSPolicy(w, r, siteID, parts[3])
		return
	}

	// Route: ACL rule ordering
	if len(parts) == 3 && parts[1] == "acl-rules" && parts[2] == "ordering" {
		m.handleACLRuleOrdering(w, r, siteID)
		return
	}

	// Route: ACL rules collection
	if len(parts) == 2 && parts[1] == "acl-rules" {
		m.handleACLRules(w, r, siteID)
		return
	}

	// Route: ACL rules single item
	if len(parts) == 3 && parts[1] == "acl-rules" {
		m.handleACLRule(w, r, siteID, parts[2])
		return
	}

	// Route: traffic matching lists collection
	if len(parts) == 2 && parts[1] == "traffic-matching-lists" {
		m.handleTrafficLists(w, r, siteID)
		return
	}

	// Route: traffic matching lists single item
	if len(parts) == 3 && parts[1] == "traffic-matching-lists" {
		m.handleTrafficList(w, r, siteID, parts[2])
		return
	}

	http.NotFound(w, r)
}

func (m *mockUnifiAPI) handleFWPolicies(w http.ResponseWriter, r *http.Request, siteID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		policies := m.fwPolicies[siteID]
		if policies == nil {
			policies = []FirewallPolicy{}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"data": policies})
	case http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		var policy FirewallPolicy
		json.Unmarshal(body, &policy)
		policy.ID = m.genID()
		m.fwPolicies[siteID] = append(m.fwPolicies[siteID], policy)
		json.NewEncoder(w).Encode(policy)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *mockUnifiAPI) handleFWPolicy(w http.ResponseWriter, r *http.Request, siteID, policyID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	policies := m.fwPolicies[siteID]
	idx := -1
	for i, p := range policies {
		if p.ID == policyID {
			idx = i
			break
		}
	}

	switch r.Method {
	case http.MethodGet:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		json.NewEncoder(w).Encode(policies[idx])
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		var policy FirewallPolicy
		json.Unmarshal(body, &policy)
		policy.ID = policyID
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		m.fwPolicies[siteID][idx] = policy
		json.NewEncoder(w).Encode(policy)
	case http.MethodPatch:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		body, _ := io.ReadAll(r.Body)
		var patch FirewallPolicyPatch
		json.Unmarshal(body, &patch)
		if patch.LoggingEnabled != nil {
			m.fwPolicies[siteID][idx].LoggingEnabled = *patch.LoggingEnabled
		}
		json.NewEncoder(w).Encode(m.fwPolicies[siteID][idx])
	case http.MethodDelete:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		m.fwPolicies[siteID] = append(policies[:idx], policies[idx+1:]...)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *mockUnifiAPI) handleDNSPolicies(w http.ResponseWriter, r *http.Request, siteID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		policies := m.dnsPolicies[siteID]
		if policies == nil {
			policies = []DNSPolicy{}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"data": policies})
	case http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		var policy DNSPolicy
		json.Unmarshal(body, &policy)
		policy.ID = m.genID()
		m.dnsPolicies[siteID] = append(m.dnsPolicies[siteID], policy)
		json.NewEncoder(w).Encode(policy)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *mockUnifiAPI) handleDNSPolicy(w http.ResponseWriter, r *http.Request, siteID, policyID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	policies := m.dnsPolicies[siteID]
	idx := -1
	for i, p := range policies {
		if p.ID == policyID {
			idx = i
			break
		}
	}

	switch r.Method {
	case http.MethodGet:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		json.NewEncoder(w).Encode(policies[idx])
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		var policy DNSPolicy
		json.Unmarshal(body, &policy)
		policy.ID = policyID
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		m.dnsPolicies[siteID][idx] = policy
		json.NewEncoder(w).Encode(policy)
	case http.MethodDelete:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		m.dnsPolicies[siteID] = append(policies[:idx], policies[idx+1:]...)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// REST API handlers wrap responses in {"meta":{"rc":"ok"},"data":[...]}

func (m *mockUnifiAPI) restOK(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]string{"rc": "ok"},
		"data": data,
	})
}

func (m *mockUnifiAPI) restError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]string{"rc": "error", "msg": msg},
	})
}

func (m *mockUnifiAPI) handleRestClients(w http.ResponseWriter, r *http.Request, siteID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	clients := m.clients[siteID]
	if clients == nil {
		clients = []ClientDevice{}
	}
	m.restOK(w, clients)
}

func (m *mockUnifiAPI) handleRestClient(w http.ResponseWriter, r *http.Request, siteID, clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	clients := m.clients[siteID]
	idx := -1
	for i, c := range clients {
		if c.ID == clientID {
			idx = i
			break
		}
	}

	switch r.Method {
	case http.MethodGet:
		if idx == -1 {
			m.restError(w, http.StatusNotFound, "api.err.ClientNotFound")
			return
		}
		m.restOK(w, []ClientDevice{clients[idx]})
	case http.MethodPut:
		if idx == -1 {
			m.restError(w, http.StatusNotFound, "api.err.ClientNotFound")
			return
		}
		body, _ := io.ReadAll(r.Body)
		var update ClientDevice
		json.Unmarshal(body, &update)
		// Preserve ID and MAC from existing client
		update.ID = clientID
		if update.MAC == "" {
			update.MAC = clients[idx].MAC
		}
		if update.Name == "" {
			update.Name = clients[idx].Name
		}
		m.clients[siteID][idx] = update
		m.restOK(w, []ClientDevice{update})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// --- Firewall Zone CRUD handlers ---

func (m *mockUnifiAPI) handleFirewallZones(w http.ResponseWriter, r *http.Request, siteID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		zones := m.zones[siteID]
		if zones == nil {
			zones = []FirewallZone{}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"data": zones})
	case http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		var zone FirewallZone
		json.Unmarshal(body, &zone)
		zone.ID = m.genID()
		m.zones[siteID] = append(m.zones[siteID], zone)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(zone)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *mockUnifiAPI) handleFirewallZone(w http.ResponseWriter, r *http.Request, siteID, zoneID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	zones := m.zones[siteID]
	idx := -1
	for i, z := range zones {
		if z.ID == zoneID {
			idx = i
			break
		}
	}

	switch r.Method {
	case http.MethodGet:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		json.NewEncoder(w).Encode(zones[idx])
	case http.MethodPut:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		body, _ := io.ReadAll(r.Body)
		var zone FirewallZone
		json.Unmarshal(body, &zone)
		zone.ID = zoneID
		m.zones[siteID][idx] = zone
		json.NewEncoder(w).Encode(zone)
	case http.MethodDelete:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		m.zones[siteID] = append(zones[:idx], zones[idx+1:]...)
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// --- Firewall Policy Ordering handlers ---

func (m *mockUnifiAPI) handleFWPolicyOrdering(w http.ResponseWriter, r *http.Request, siteID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		ordering := m.fwPolicyOrdering[siteID]
		if ordering == nil {
			ordering = []string{}
		}
		json.NewEncoder(w).Encode(ordering)
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		var req FirewallPolicyOrdering
		json.Unmarshal(body, &req)
		m.fwPolicyOrdering[siteID] = req.PolicyIDs
		json.NewEncoder(w).Encode(req.PolicyIDs)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// --- ACL Rule CRUD handlers ---

func (m *mockUnifiAPI) handleACLRules(w http.ResponseWriter, r *http.Request, siteID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		rules := m.aclRules[siteID]
		if rules == nil {
			rules = []ACLRule{}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"data": rules})
	case http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		var rule ACLRule
		json.Unmarshal(body, &rule)
		rule.ID = m.genID()
		m.aclRules[siteID] = append(m.aclRules[siteID], rule)
		json.NewEncoder(w).Encode(rule)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *mockUnifiAPI) handleACLRule(w http.ResponseWriter, r *http.Request, siteID, ruleID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rules := m.aclRules[siteID]
	idx := -1
	for i, rule := range rules {
		if rule.ID == ruleID {
			idx = i
			break
		}
	}

	switch r.Method {
	case http.MethodGet:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		json.NewEncoder(w).Encode(rules[idx])
	case http.MethodPut:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rule ACLRule
		json.Unmarshal(body, &rule)
		rule.ID = ruleID
		m.aclRules[siteID][idx] = rule
		json.NewEncoder(w).Encode(rule)
	case http.MethodDelete:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		m.aclRules[siteID] = append(rules[:idx], rules[idx+1:]...)
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *mockUnifiAPI) handleACLRuleOrdering(w http.ResponseWriter, r *http.Request, siteID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		ordering := m.aclRuleOrdering[siteID]
		if ordering == nil {
			ordering = []string{}
		}
		json.NewEncoder(w).Encode(ordering)
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		var req ACLRuleOrdering
		json.Unmarshal(body, &req)
		m.aclRuleOrdering[siteID] = req.RuleIDs
		json.NewEncoder(w).Encode(req.RuleIDs)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// --- Traffic Matching List CRUD handlers ---

func (m *mockUnifiAPI) handleTrafficLists(w http.ResponseWriter, r *http.Request, siteID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		lists := m.trafficLists[siteID]
		if lists == nil {
			lists = []TrafficMatchingList{}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"data": lists})
	case http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		var list TrafficMatchingList
		json.Unmarshal(body, &list)
		list.ID = m.genID()
		m.trafficLists[siteID] = append(m.trafficLists[siteID], list)
		json.NewEncoder(w).Encode(list)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *mockUnifiAPI) handleTrafficList(w http.ResponseWriter, r *http.Request, siteID, listID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	lists := m.trafficLists[siteID]
	idx := -1
	for i, l := range lists {
		if l.ID == listID {
			idx = i
			break
		}
	}

	switch r.Method {
	case http.MethodGet:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		json.NewEncoder(w).Encode(lists[idx])
	case http.MethodPut:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		body, _ := io.ReadAll(r.Body)
		var list TrafficMatchingList
		json.Unmarshal(body, &list)
		list.ID = listID
		m.trafficLists[siteID][idx] = list
		json.NewEncoder(w).Encode(list)
	case http.MethodDelete:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		m.trafficLists[siteID] = append(lists[:idx], lists[idx+1:]...)
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

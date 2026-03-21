package unifi

import (
	"testing"
)

// --- Firewall Zone CRUD ---

func TestCreateFirewallZone_HappyPath(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	created, err := client.CreateFirewallZone(FirewallZone{
		Name:       "DMZ",
		NetworkIDs: []string{"net-1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created.ID == "" {
		t.Error("expected server-generated ID")
	}
	if created.Name != "DMZ" {
		t.Errorf("expected 'DMZ', got %q", created.Name)
	}
}

func TestCreateFirewallZone_ServerError(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.SetError("POST", "/v1/sites/site-1/firewall/zones", 400)

	client := NewClient(srv.URL, "test-key", "site-1", false)
	_, err := client.CreateFirewallZone(FirewallZone{Name: "Test"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetFirewallZone_FromCache(t *testing.T) {
	srv, mock := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	// Should find zone-lan from the default mock data via the list cache.
	zone, err := client.GetFirewallZone("zone-lan")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if zone.Name != "LAN" {
		t.Errorf("expected 'LAN', got %q", zone.Name)
	}

	// Second get should reuse cache — only 1 list call.
	zone2, err := client.GetFirewallZone("zone-wan")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if zone2.Name != "WAN" {
		t.Errorf("expected 'WAN', got %q", zone2.Name)
	}

	callCount := mock.GetCallCount("GET", "/v1/sites/site-1/firewall/zones")
	if callCount != 1 {
		t.Errorf("expected 1 list call for 2 gets, got %d", callCount)
	}
}

func TestGetFirewallZone_NotFound_FallbackToDirectGET(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	_, err := client.GetFirewallZone("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent zone, got nil")
	}
	if !contains(err.Error(), "404") {
		t.Errorf("expected 404 in error, got: %s", err.Error())
	}
}

func TestUpdateFirewallZone_HappyPath(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	updated, err := client.UpdateFirewallZone("zone-lan", FirewallZone{
		Name:       "LAN-Updated",
		NetworkIDs: []string{"net-1", "net-3"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Name != "LAN-Updated" {
		t.Errorf("expected 'LAN-Updated', got %q", updated.Name)
	}
	if updated.ID != "zone-lan" {
		t.Errorf("expected ID preserved as 'zone-lan', got %q", updated.ID)
	}
}

func TestUpdateFirewallZone_NotFound(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	_, err := client.UpdateFirewallZone("nonexistent", FirewallZone{Name: "X"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestDeleteFirewallZone_HappyPath(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	err := client.DeleteFirewallZone("zone-lan")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's gone
	client.invalidateZoneCache()
	zones, _ := client.ListFirewallZones()
	for _, z := range zones {
		if z.ID == "zone-lan" {
			t.Error("zone-lan should have been deleted")
		}
	}
}

func TestDeleteFirewallZone_NotFound(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	err := client.DeleteFirewallZone("nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestFirewallZone_FullCRUDCycle(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	// Create
	created, err := client.CreateFirewallZone(FirewallZone{
		Name:       "TestZone",
		NetworkIDs: []string{"net-1"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Read
	client.invalidateZoneCache()
	got, err := client.GetFirewallZone(created.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Name != "TestZone" {
		t.Errorf("read: expected 'TestZone', got %q", got.Name)
	}

	// Update
	updated, err := client.UpdateFirewallZone(created.ID, FirewallZone{
		Name:       "UpdatedZone",
		NetworkIDs: []string{"net-2"},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "UpdatedZone" {
		t.Errorf("update: expected 'UpdatedZone', got %q", updated.Name)
	}

	// Delete
	err = client.DeleteFirewallZone(created.ID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Verify deleted
	client.invalidateZoneCache()
	_, err = client.GetFirewallZone(created.ID)
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestCreateFirewallZone_InvalidatesCache(t *testing.T) {
	srv, mock := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	// Populate cache
	zones1, _ := client.ListFirewallZones()
	initial := len(zones1)

	// Create — should invalidate cache
	client.CreateFirewallZone(FirewallZone{Name: "New", NetworkIDs: []string{}})

	// List again — should refetch
	zones2, _ := client.ListFirewallZones()
	if len(zones2) != initial+1 {
		t.Errorf("expected %d zones after create, got %d", initial+1, len(zones2))
	}

	callCount := mock.GetCallCount("GET", "/v1/sites/site-1/firewall/zones")
	if callCount != 2 {
		t.Errorf("expected 2 list calls (initial + after invalidation), got %d", callCount)
	}
}

// --- Firewall Policy Ordering ---

func TestGetFirewallPolicyOrdering_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.fwPolicyOrdering["site-1"] = []string{"fw-1", "fw-2", "fw-3"}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	ordering, err := client.GetFirewallPolicyOrdering()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ordering) != 3 {
		t.Fatalf("expected 3 policy IDs, got %d", len(ordering))
	}
	if ordering[0] != "fw-1" {
		t.Errorf("expected first ID 'fw-1', got %q", ordering[0])
	}
}

func TestGetFirewallPolicyOrdering_Empty(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	ordering, err := client.GetFirewallPolicyOrdering()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ordering) != 0 {
		t.Fatalf("expected empty ordering, got %d", len(ordering))
	}
}

func TestGetFirewallPolicyOrdering_ServerError(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.SetError("GET", "/v1/sites/site-1/firewall/policies/ordering", 500)

	client := NewClient(srv.URL, "test-key", "site-1", false)
	_, err := client.GetFirewallPolicyOrdering()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestUpdateFirewallPolicyOrdering_HappyPath(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	result, err := client.UpdateFirewallPolicyOrdering(FirewallPolicyOrdering{
		PolicyIDs: []string{"fw-3", "fw-1", "fw-2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3 IDs returned, got %d", len(result))
	}
	if result[0] != "fw-3" {
		t.Errorf("expected first ID 'fw-3', got %q", result[0])
	}

	// Verify ordering was stored
	ordering, _ := client.GetFirewallPolicyOrdering()
	if len(ordering) != 3 || ordering[0] != "fw-3" {
		t.Error("ordering not persisted correctly in mock")
	}
}

func TestUpdateFirewallPolicyOrdering_ServerError(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.SetError("PUT", "/v1/sites/site-1/firewall/policies/ordering", 400)

	client := NewClient(srv.URL, "test-key", "site-1", false)
	_, err := client.UpdateFirewallPolicyOrdering(FirewallPolicyOrdering{PolicyIDs: []string{"a"}})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --- Firewall Policy PATCH ---

func TestPatchFirewallPolicy_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.fwPolicies["site-1"] = []FirewallPolicy{
		{ID: "fw-1", Name: "Test", LoggingEnabled: false},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)

	enabled := true
	result, err := client.PatchFirewallPolicy("fw-1", FirewallPolicyPatch{
		LoggingEnabled: &enabled,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.LoggingEnabled {
		t.Error("expected LoggingEnabled to be true after patch")
	}
	if result.Name != "Test" {
		t.Errorf("expected name preserved as 'Test', got %q", result.Name)
	}
}

func TestPatchFirewallPolicy_NotFound(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	enabled := true
	_, err := client.PatchFirewallPolicy("nonexistent", FirewallPolicyPatch{
		LoggingEnabled: &enabled,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestPatchFirewallPolicy_ServerError(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.SetError("PATCH", "/v1/sites/site-1/firewall/policies/fw-1", 500)

	client := NewClient(srv.URL, "test-key", "site-1", false)
	enabled := true
	_, err := client.PatchFirewallPolicy("fw-1", FirewallPolicyPatch{LoggingEnabled: &enabled})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --- ACL Rules CRUD ---

func TestCreateACLRule_HappyPath(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	created, err := client.CreateACLRule(ACLRule{
		Type:    "IPV4",
		Name:    "Block Guest",
		Enabled: true,
		Action:  "BLOCK",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created.ID == "" {
		t.Error("expected server-generated ID")
	}
	if created.Name != "Block Guest" {
		t.Errorf("expected 'Block Guest', got %q", created.Name)
	}
}

func TestCreateACLRule_ServerError(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.SetError("POST", "/v1/sites/site-1/acl-rules", 400)

	client := NewClient(srv.URL, "test-key", "site-1", false)
	_, err := client.CreateACLRule(ACLRule{Name: "Test"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestListACLRules_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.aclRules["site-1"] = []ACLRule{
		{ID: "acl-1", Name: "Rule1", Type: "IPV4"},
		{ID: "acl-2", Name: "Rule2", Type: "MAC"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	rules, err := client.ListACLRules()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestListACLRules_Empty(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	rules, err := client.ListACLRules()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(rules))
	}
}

func TestGetACLRule_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.aclRules["site-1"] = []ACLRule{
		{ID: "acl-1", Name: "Rule1", Type: "IPV4", Action: "BLOCK"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	rule, err := client.GetACLRule("acl-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule.Name != "Rule1" {
		t.Errorf("expected 'Rule1', got %q", rule.Name)
	}
	if rule.Action != "BLOCK" {
		t.Errorf("expected action 'BLOCK', got %q", rule.Action)
	}
}

func TestGetACLRule_NotFound(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	_, err := client.GetACLRule("nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestUpdateACLRule_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.aclRules["site-1"] = []ACLRule{
		{ID: "acl-1", Name: "Old Name", Type: "IPV4", Action: "BLOCK"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	updated, err := client.UpdateACLRule("acl-1", ACLRule{
		Name:    "New Name",
		Type:    "IPV4",
		Action:  "ALLOW",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Name != "New Name" {
		t.Errorf("expected 'New Name', got %q", updated.Name)
	}
	if updated.ID != "acl-1" {
		t.Errorf("expected ID preserved as 'acl-1', got %q", updated.ID)
	}
}

func TestUpdateACLRule_NotFound(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	_, err := client.UpdateACLRule("nonexistent", ACLRule{Name: "X"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestDeleteACLRule_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.aclRules["site-1"] = []ACLRule{
		{ID: "acl-1", Name: "To Delete"},
		{ID: "acl-2", Name: "Keep"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	err := client.DeleteACLRule("acl-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's gone
	rules, _ := client.ListACLRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule remaining, got %d", len(rules))
	}
	if rules[0].ID != "acl-2" {
		t.Errorf("expected 'acl-2' remaining, got %q", rules[0].ID)
	}
}

func TestDeleteACLRule_NotFound(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	err := client.DeleteACLRule("nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestACLRule_FullCRUDCycle(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	// Create
	created, err := client.CreateACLRule(ACLRule{
		Type:    "IPV4",
		Name:    "CRUD Test",
		Enabled: true,
		Action:  "BLOCK",
		SourceFilter: &ACLFilter{
			IPAddressesOrSubnets: []string{"10.0.0.0/24"},
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Read
	got, err := client.GetACLRule(created.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Name != "CRUD Test" {
		t.Errorf("read: expected 'CRUD Test', got %q", got.Name)
	}

	// Update
	updated, err := client.UpdateACLRule(created.ID, ACLRule{
		Type:    "IPV4",
		Name:    "Updated",
		Enabled: false,
		Action:  "ALLOW",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Updated" {
		t.Errorf("update: expected 'Updated', got %q", updated.Name)
	}

	// Delete
	err = client.DeleteACLRule(created.ID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Verify deleted
	_, err = client.GetACLRule(created.ID)
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestACLRule_WithFilters(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	created, err := client.CreateACLRule(ACLRule{
		Type:    "IPV4",
		Name:    "Filtered Rule",
		Enabled: true,
		Action:  "BLOCK",
		ProtocolFilter: []string{"TCP", "UDP"},
		NetworkID:      "net-1",
		EnforcingDeviceFilter: &ACLDeviceFilter{
			DeviceIDs: []string{"dev-1", "dev-2"},
		},
		SourceFilter: &ACLFilter{
			Type:                 "IP",
			IPAddressesOrSubnets: []string{"10.0.0.0/8"},
			PortFilter:           []int{80, 443},
		},
		DestinationFilter: &ACLFilter{
			Type:         "MAC",
			MACAddresses: []string{"aa:bb:cc:dd:ee:ff"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := client.GetACLRule(created.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.ProtocolFilter) != 2 {
		t.Errorf("expected 2 protocol filters, got %d", len(got.ProtocolFilter))
	}
	if got.SourceFilter == nil {
		t.Fatal("expected source filter to be non-nil")
	}
	if len(got.SourceFilter.IPAddressesOrSubnets) != 1 {
		t.Errorf("expected 1 IP filter, got %d", len(got.SourceFilter.IPAddressesOrSubnets))
	}
	if got.EnforcingDeviceFilter == nil || len(got.EnforcingDeviceFilter.DeviceIDs) != 2 {
		t.Error("expected enforcing device filter with 2 devices")
	}
}

// --- ACL Rule Ordering ---

func TestGetACLRuleOrdering_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.aclRuleOrdering["site-1"] = []string{"acl-1", "acl-2"}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	ordering, err := client.GetACLRuleOrdering()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ordering) != 2 {
		t.Fatalf("expected 2 rule IDs, got %d", len(ordering))
	}
}

func TestGetACLRuleOrdering_Empty(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	ordering, err := client.GetACLRuleOrdering()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ordering) != 0 {
		t.Fatalf("expected empty ordering, got %d", len(ordering))
	}
}

func TestUpdateACLRuleOrdering_HappyPath(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	result, err := client.UpdateACLRuleOrdering(ACLRuleOrdering{
		RuleIDs: []string{"acl-2", "acl-1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 || result[0] != "acl-2" {
		t.Errorf("expected ['acl-2','acl-1'], got %v", result)
	}

	// Verify persisted
	ordering, _ := client.GetACLRuleOrdering()
	if len(ordering) != 2 || ordering[0] != "acl-2" {
		t.Error("ordering not persisted correctly")
	}
}

func TestUpdateACLRuleOrdering_ServerError(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.SetError("PUT", "/v1/sites/site-1/acl-rules/ordering", 400)

	client := NewClient(srv.URL, "test-key", "site-1", false)
	_, err := client.UpdateACLRuleOrdering(ACLRuleOrdering{RuleIDs: []string{"a"}})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --- Traffic Matching Lists CRUD ---

func TestCreateTrafficMatchingList_HappyPath(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	created, err := client.CreateTrafficMatchingList(TrafficMatchingList{
		Type: "PORTS",
		Name: "Web Ports",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created.ID == "" {
		t.Error("expected server-generated ID")
	}
	if created.Name != "Web Ports" {
		t.Errorf("expected 'Web Ports', got %q", created.Name)
	}
	if created.Type != "PORTS" {
		t.Errorf("expected type 'PORTS', got %q", created.Type)
	}
}

func TestCreateTrafficMatchingList_ServerError(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.SetError("POST", "/v1/sites/site-1/traffic-matching-lists", 400)

	client := NewClient(srv.URL, "test-key", "site-1", false)
	_, err := client.CreateTrafficMatchingList(TrafficMatchingList{Name: "Test"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestListTrafficMatchingLists_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.trafficLists["site-1"] = []TrafficMatchingList{
		{ID: "tl-1", Type: "PORTS", Name: "Web Ports"},
		{ID: "tl-2", Type: "IPV4_ADDRESSES", Name: "Trusted IPs"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	lists, err := client.ListTrafficMatchingLists()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lists) != 2 {
		t.Fatalf("expected 2 lists, got %d", len(lists))
	}
}

func TestListTrafficMatchingLists_Empty(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	lists, err := client.ListTrafficMatchingLists()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lists) != 0 {
		t.Fatalf("expected 0 lists, got %d", len(lists))
	}
}

func TestGetTrafficMatchingList_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.trafficLists["site-1"] = []TrafficMatchingList{
		{ID: "tl-1", Type: "PORTS", Name: "Web Ports"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	list, err := client.GetTrafficMatchingList("tl-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if list.Name != "Web Ports" {
		t.Errorf("expected 'Web Ports', got %q", list.Name)
	}
}

func TestGetTrafficMatchingList_NotFound(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	_, err := client.GetTrafficMatchingList("nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestUpdateTrafficMatchingList_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.trafficLists["site-1"] = []TrafficMatchingList{
		{ID: "tl-1", Type: "PORTS", Name: "Old Name"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	updated, err := client.UpdateTrafficMatchingList("tl-1", TrafficMatchingList{
		Type: "PORTS",
		Name: "New Name",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Name != "New Name" {
		t.Errorf("expected 'New Name', got %q", updated.Name)
	}
	if updated.ID != "tl-1" {
		t.Errorf("expected ID preserved as 'tl-1', got %q", updated.ID)
	}
}

func TestUpdateTrafficMatchingList_NotFound(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	_, err := client.UpdateTrafficMatchingList("nonexistent", TrafficMatchingList{Name: "X"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestDeleteTrafficMatchingList_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.trafficLists["site-1"] = []TrafficMatchingList{
		{ID: "tl-1", Name: "Delete Me"},
		{ID: "tl-2", Name: "Keep"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	err := client.DeleteTrafficMatchingList("tl-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lists, _ := client.ListTrafficMatchingLists()
	if len(lists) != 1 {
		t.Fatalf("expected 1 list remaining, got %d", len(lists))
	}
}

func TestDeleteTrafficMatchingList_NotFound(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	err := client.DeleteTrafficMatchingList("nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestTrafficMatchingList_FullCRUDCycle(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	// Create
	created, err := client.CreateTrafficMatchingList(TrafficMatchingList{
		Type: "IPV4_ADDRESSES",
		Name: "Trusted IPs",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Read
	got, err := client.GetTrafficMatchingList(created.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Name != "Trusted IPs" {
		t.Errorf("expected 'Trusted IPs', got %q", got.Name)
	}

	// Update
	updated, err := client.UpdateTrafficMatchingList(created.ID, TrafficMatchingList{
		Type: "IPV4_ADDRESSES",
		Name: "Updated IPs",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Updated IPs" {
		t.Errorf("expected 'Updated IPs', got %q", updated.Name)
	}

	// Delete
	err = client.DeleteTrafficMatchingList(created.ID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Verify deleted
	_, err = client.GetTrafficMatchingList(created.ID)
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestTrafficMatchingList_AllTypes(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	types := []string{"PORTS", "IPV4_ADDRESSES", "IPV6_ADDRESSES"}
	for _, typ := range types {
		created, err := client.CreateTrafficMatchingList(TrafficMatchingList{
			Type: typ,
			Name: "List " + typ,
		})
		if err != nil {
			t.Fatalf("create %s: %v", typ, err)
		}
		if created.Type != typ {
			t.Errorf("expected type %q, got %q", typ, created.Type)
		}
	}

	lists, _ := client.ListTrafficMatchingLists()
	if len(lists) != 3 {
		t.Errorf("expected 3 lists, got %d", len(lists))
	}
}

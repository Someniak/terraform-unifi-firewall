package acl

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

func TestMapToAPI_MinimalRule(t *testing.T) {
	r := &ACLRuleResource{}
	diags := diag.Diagnostics{}

	model := ACLRuleResourceModel{
		Type:           types.StringValue("IPV4"),
		Name:           types.StringValue("Test Rule"),
		Enabled:        types.BoolValue(true),
		Action:         types.StringValue("BLOCK"),
		Description:    types.StringNull(),
		NetworkID:      types.StringNull(),
		ProtocolFilter: types.SetNull(types.StringType),
	}

	rule := r.mapToAPI(context.Background(), model, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if rule.Type != "IPV4" {
		t.Errorf("expected type 'IPV4', got %q", rule.Type)
	}
	if rule.Name != "Test Rule" {
		t.Errorf("expected name 'Test Rule', got %q", rule.Name)
	}
	if !rule.Enabled {
		t.Error("expected enabled true")
	}
	if rule.Action != "BLOCK" {
		t.Errorf("expected action 'BLOCK', got %q", rule.Action)
	}
	if rule.Description != "" {
		t.Errorf("expected empty description, got %q", rule.Description)
	}
	if rule.SourceFilter != nil {
		t.Error("expected nil source filter")
	}
	if rule.DestinationFilter != nil {
		t.Error("expected nil destination filter")
	}
}

func TestMapToAPI_WithAllFields(t *testing.T) {
	r := &ACLRuleResource{}
	diags := diag.Diagnostics{}
	ctx := context.Background()

	protoSet, _ := types.SetValueFrom(ctx, types.StringType, []string{"TCP", "UDP"})
	deviceSet, _ := types.SetValueFrom(ctx, types.StringType, []string{"dev-1"})
	ipSet, _ := types.SetValueFrom(ctx, types.StringType, []string{"10.0.0.0/24", "192.168.1.1"})
	portSet, _ := types.SetValueFrom(ctx, types.Int64Type, []int64{80, 443})
	macSet, _ := types.SetValueFrom(ctx, types.StringType, []string{"aa:bb:cc:dd:ee:ff"})

	model := ACLRuleResourceModel{
		Type:           types.StringValue("IPV4"),
		Name:           types.StringValue("Full Rule"),
		Description:    types.StringValue("A test rule"),
		Enabled:        types.BoolValue(false),
		Action:         types.StringValue("ALLOW"),
		ProtocolFilter: protoSet,
		NetworkID:      types.StringValue("net-1"),
		EnforcingDeviceFilter: &DeviceFilterModel{
			DeviceIDs: deviceSet,
		},
		SourceFilter: &ACLFilterModel{
			Type:                 types.StringValue("IP"),
			IPAddressesOrSubnets: ipSet,
			PortFilter:           portSet,
			NetworkIDs:           types.SetNull(types.StringType),
			MACAddresses:         types.SetNull(types.StringType),
		},
		DestinationFilter: &ACLFilterModel{
			Type:                 types.StringValue("MAC"),
			IPAddressesOrSubnets: types.SetNull(types.StringType),
			PortFilter:           types.SetNull(types.Int64Type),
			NetworkIDs:           types.SetNull(types.StringType),
			MACAddresses:         macSet,
		},
	}

	rule := r.mapToAPI(ctx, model, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if rule.Description != "A test rule" {
		t.Errorf("expected description 'A test rule', got %q", rule.Description)
	}
	if rule.NetworkID != "net-1" {
		t.Errorf("expected network ID 'net-1', got %q", rule.NetworkID)
	}
	if len(rule.ProtocolFilter) != 2 {
		t.Fatalf("expected 2 protocol filters, got %d", len(rule.ProtocolFilter))
	}
	if rule.EnforcingDeviceFilter == nil || len(rule.EnforcingDeviceFilter.DeviceIDs) != 1 {
		t.Fatal("expected enforcing device filter with 1 device")
	}
	if rule.SourceFilter == nil {
		t.Fatal("expected non-nil source filter")
	}
	if len(rule.SourceFilter.IPAddressesOrSubnets) != 2 {
		t.Errorf("expected 2 IP addresses, got %d", len(rule.SourceFilter.IPAddressesOrSubnets))
	}
	if len(rule.SourceFilter.PortFilter) != 2 {
		t.Errorf("expected 2 ports, got %d", len(rule.SourceFilter.PortFilter))
	}
	if rule.DestinationFilter == nil {
		t.Fatal("expected non-nil destination filter")
	}
	if len(rule.DestinationFilter.MACAddresses) != 1 {
		t.Errorf("expected 1 MAC address, got %d", len(rule.DestinationFilter.MACAddresses))
	}
}

func TestMapFromAPI_MinimalRule(t *testing.T) {
	r := &ACLRuleResource{}
	diags := diag.Diagnostics{}
	ctx := context.Background()

	rule := &unifi.ACLRule{
		ID:      "acl-1",
		Type:    "MAC",
		Name:    "MAC Rule",
		Enabled: true,
		Action:  "ALLOW",
	}

	var model ACLRuleResourceModel
	r.mapFromAPI(ctx, rule, &model, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if model.ID.ValueString() != "acl-1" {
		t.Errorf("expected ID 'acl-1', got %q", model.ID.ValueString())
	}
	if model.Type.ValueString() != "MAC" {
		t.Errorf("expected type 'MAC', got %q", model.Type.ValueString())
	}
	if model.Description.IsNull() != true {
		t.Error("expected null description")
	}
	if model.NetworkID.IsNull() != true {
		t.Error("expected null network ID")
	}
	if model.ProtocolFilter.IsNull() != true {
		t.Error("expected null protocol filter")
	}
}

func TestMapFromAPI_WithFilters(t *testing.T) {
	r := &ACLRuleResource{}
	diags := diag.Diagnostics{}
	ctx := context.Background()

	rule := &unifi.ACLRule{
		ID:             "acl-1",
		Type:           "IPV4",
		Name:           "Full Rule",
		Description:    "Desc",
		Enabled:        true,
		Action:         "BLOCK",
		ProtocolFilter: []string{"TCP"},
		NetworkID:      "net-1",
		EnforcingDeviceFilter: &unifi.ACLDeviceFilter{
			DeviceIDs: []string{"dev-1", "dev-2"},
		},
		SourceFilter: &unifi.ACLFilter{
			Type:                 "IP",
			IPAddressesOrSubnets: []string{"10.0.0.0/8"},
			PortFilter:           []int{22, 80},
		},
		DestinationFilter: &unifi.ACLFilter{
			Type:       "NETWORK",
			NetworkIDs: []string{"net-2"},
		},
	}

	var model ACLRuleResourceModel
	r.mapFromAPI(ctx, rule, &model, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if model.Description.ValueString() != "Desc" {
		t.Errorf("expected description 'Desc', got %q", model.Description.ValueString())
	}
	if model.NetworkID.ValueString() != "net-1" {
		t.Errorf("expected network ID 'net-1', got %q", model.NetworkID.ValueString())
	}
	if model.EnforcingDeviceFilter == nil {
		t.Fatal("expected non-nil enforcing device filter")
	}
	if model.SourceFilter == nil {
		t.Fatal("expected non-nil source filter")
	}
	if model.SourceFilter.Type.ValueString() != "IP" {
		t.Errorf("expected source filter type 'IP', got %q", model.SourceFilter.Type.ValueString())
	}
	if model.DestinationFilter == nil {
		t.Fatal("expected non-nil destination filter")
	}
}

func TestMapFromAPI_EmptyFilters(t *testing.T) {
	r := &ACLRuleResource{}
	diags := diag.Diagnostics{}
	ctx := context.Background()

	rule := &unifi.ACLRule{
		ID:      "acl-1",
		Type:    "IPV4",
		Name:    "Minimal",
		Enabled: true,
		Action:  "BLOCK",
		SourceFilter: &unifi.ACLFilter{
			Type: "IP",
			// All filter arrays empty
		},
	}

	var model ACLRuleResourceModel
	r.mapFromAPI(ctx, rule, &model, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if model.SourceFilter == nil {
		t.Fatal("expected non-nil source filter")
	}
	if !model.SourceFilter.IPAddressesOrSubnets.IsNull() {
		t.Error("expected null IP addresses for empty array")
	}
	if !model.SourceFilter.PortFilter.IsNull() {
		t.Error("expected null port filter for empty array")
	}
}

func TestMapRoundTrip(t *testing.T) {
	r := &ACLRuleResource{}
	ctx := context.Background()

	// Start with an API rule
	original := &unifi.ACLRule{
		ID:             "acl-1",
		Type:           "IPV4",
		Name:           "Round Trip",
		Description:    "Test round trip",
		Enabled:        true,
		Action:         "BLOCK",
		ProtocolFilter: []string{"TCP", "UDP"},
		NetworkID:      "net-1",
		SourceFilter: &unifi.ACLFilter{
			Type:                 "IP",
			IPAddressesOrSubnets: []string{"10.0.0.0/24"},
			PortFilter:           []int{443},
		},
	}

	// API -> Model
	diags1 := diag.Diagnostics{}
	var model ACLRuleResourceModel
	r.mapFromAPI(ctx, original, &model, &diags1)
	if diags1.HasError() {
		t.Fatalf("mapFromAPI: %v", diags1)
	}

	// Model -> API
	diags2 := diag.Diagnostics{}
	roundTripped := r.mapToAPI(ctx, model, &diags2)
	if diags2.HasError() {
		t.Fatalf("mapToAPI: %v", diags2)
	}

	// Verify key fields survived
	if roundTripped.Type != original.Type {
		t.Errorf("type: expected %q, got %q", original.Type, roundTripped.Type)
	}
	if roundTripped.Name != original.Name {
		t.Errorf("name: expected %q, got %q", original.Name, roundTripped.Name)
	}
	if roundTripped.Action != original.Action {
		t.Errorf("action: expected %q, got %q", original.Action, roundTripped.Action)
	}
	if roundTripped.NetworkID != original.NetworkID {
		t.Errorf("networkID: expected %q, got %q", original.NetworkID, roundTripped.NetworkID)
	}
	if roundTripped.SourceFilter == nil {
		t.Fatal("expected non-nil source filter after round trip")
	}
	if len(roundTripped.SourceFilter.IPAddressesOrSubnets) != 1 {
		t.Errorf("expected 1 IP after round trip, got %d", len(roundTripped.SourceFilter.IPAddressesOrSubnets))
	}
	if len(roundTripped.SourceFilter.PortFilter) != 1 {
		t.Errorf("expected 1 port after round trip, got %d", len(roundTripped.SourceFilter.PortFilter))
	}
}

package acl

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

func (r *ACLRuleResource) mapToAPI(ctx context.Context, data ACLRuleResourceModel, diags *diag.Diagnostics) unifi.ACLRule {
	rule := unifi.ACLRule{
		Type:    data.Type.ValueString(),
		Name:    data.Name.ValueString(),
		Enabled: data.Enabled.ValueBool(),
		Action:  data.Action.ValueString(),
	}

	if !data.Description.IsNull() {
		rule.Description = data.Description.ValueString()
	}
	if !data.NetworkID.IsNull() {
		rule.NetworkID = data.NetworkID.ValueString()
	}

	if !data.ProtocolFilter.IsNull() {
		var protocols []string
		diags.Append(data.ProtocolFilter.ElementsAs(ctx, &protocols, false)...)
		rule.ProtocolFilter = protocols
	}

	if data.EnforcingDeviceFilter != nil && !data.EnforcingDeviceFilter.DeviceIDs.IsNull() {
		var deviceIDs []string
		diags.Append(data.EnforcingDeviceFilter.DeviceIDs.ElementsAs(ctx, &deviceIDs, false)...)
		rule.EnforcingDeviceFilter = &unifi.ACLDeviceFilter{DeviceIDs: deviceIDs}
	}

	if data.SourceFilter != nil {
		rule.SourceFilter = mapACLFilterToAPI(ctx, data.SourceFilter, diags)
	}
	if data.DestinationFilter != nil {
		rule.DestinationFilter = mapACLFilterToAPI(ctx, data.DestinationFilter, diags)
	}

	return rule
}

func mapACLFilterToAPI(ctx context.Context, f *ACLFilterModel, diags *diag.Diagnostics) *unifi.ACLFilter {
	if f == nil {
		return nil
	}

	filter := &unifi.ACLFilter{}

	if !f.Type.IsNull() {
		filter.Type = f.Type.ValueString()
	}

	if !f.IPAddressesOrSubnets.IsNull() {
		var items []string
		diags.Append(f.IPAddressesOrSubnets.ElementsAs(ctx, &items, false)...)
		filter.IPAddressesOrSubnets = items
	}

	if !f.PortFilter.IsNull() {
		var ports []int
		// Set of int64 -> convert
		var ports64 []int64
		diags.Append(f.PortFilter.ElementsAs(ctx, &ports64, false)...)
		for _, p := range ports64 {
			ports = append(ports, int(p))
		}
		filter.PortFilter = ports
	}

	if !f.NetworkIDs.IsNull() {
		var items []string
		diags.Append(f.NetworkIDs.ElementsAs(ctx, &items, false)...)
		filter.NetworkIDs = items
	}

	if !f.MACAddresses.IsNull() {
		var items []string
		diags.Append(f.MACAddresses.ElementsAs(ctx, &items, false)...)
		filter.MACAddresses = items
	}

	return filter
}

func (r *ACLRuleResource) mapFromAPI(ctx context.Context, rule *unifi.ACLRule, data *ACLRuleResourceModel, diags *diag.Diagnostics) {
	data.ID = types.StringValue(rule.ID)
	data.Type = types.StringValue(rule.Type)
	data.Name = types.StringValue(rule.Name)
	data.Enabled = types.BoolValue(rule.Enabled)
	data.Action = types.StringValue(rule.Action)

	if rule.Description != "" {
		data.Description = types.StringValue(rule.Description)
	} else {
		data.Description = types.StringNull()
	}

	if rule.NetworkID != "" {
		data.NetworkID = types.StringValue(rule.NetworkID)
	} else {
		data.NetworkID = types.StringNull()
	}

	if len(rule.ProtocolFilter) > 0 {
		data.ProtocolFilter, _ = types.SetValueFrom(ctx, types.StringType, rule.ProtocolFilter)
	} else {
		data.ProtocolFilter = types.SetNull(types.StringType)
	}

	if rule.EnforcingDeviceFilter != nil && len(rule.EnforcingDeviceFilter.DeviceIDs) > 0 {
		ids, _ := types.SetValueFrom(ctx, types.StringType, rule.EnforcingDeviceFilter.DeviceIDs)
		data.EnforcingDeviceFilter = &DeviceFilterModel{DeviceIDs: ids}
	}

	data.SourceFilter = mapACLFilterFromAPI(ctx, rule.SourceFilter)
	data.DestinationFilter = mapACLFilterFromAPI(ctx, rule.DestinationFilter)
}

func mapACLFilterFromAPI(ctx context.Context, f *unifi.ACLFilter) *ACLFilterModel {
	if f == nil {
		return nil
	}

	model := &ACLFilterModel{}

	if f.Type != "" {
		model.Type = types.StringValue(f.Type)
	} else {
		model.Type = types.StringNull()
	}

	if len(f.IPAddressesOrSubnets) > 0 {
		model.IPAddressesOrSubnets, _ = types.SetValueFrom(ctx, types.StringType, f.IPAddressesOrSubnets)
	} else {
		model.IPAddressesOrSubnets = types.SetNull(types.StringType)
	}

	if len(f.PortFilter) > 0 {
		ports := make([]int64, len(f.PortFilter))
		for i, p := range f.PortFilter {
			ports[i] = int64(p)
		}
		model.PortFilter, _ = types.SetValueFrom(ctx, types.Int64Type, ports)
	} else {
		model.PortFilter = types.SetNull(types.Int64Type)
	}

	if len(f.NetworkIDs) > 0 {
		model.NetworkIDs, _ = types.SetValueFrom(ctx, types.StringType, f.NetworkIDs)
	} else {
		model.NetworkIDs = types.SetNull(types.StringType)
	}

	if len(f.MACAddresses) > 0 {
		model.MACAddresses, _ = types.SetValueFrom(ctx, types.StringType, f.MACAddresses)
	} else {
		model.MACAddresses = types.SetNull(types.StringType)
	}

	return model
}

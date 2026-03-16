package firewall

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

func (r *FirewallPolicyResource) mapFromAPI(ctx context.Context, p *unifi.FirewallPolicy, data *FirewallPolicyResourceModel) {
	data.ID = types.StringValue(p.ID)
	data.Enabled = types.BoolValue(p.Enabled)
	data.Name = types.StringValue(p.Name)
	if p.Description != "" {
		data.Description = types.StringValue(p.Description)
	} else {
		data.Description = types.StringNull()
	}
	actionType := p.Action.Type
	data.Action = &ActionModel{
		Type: types.StringValue(actionType),
	}
	if p.Action.AllowReturnTraffic != nil {
		data.Action.AllowReturnTraffic = types.BoolValue(*p.Action.AllowReturnTraffic)
	} else {
		data.Action.AllowReturnTraffic = types.BoolValue(false)
	}
	data.Source = &SourceDestModel{
		ZoneID: types.StringValue(p.Source.ZoneID),
	}
	data.Destination = &SourceDestModel{
		ZoneID: types.StringValue(p.Destination.ZoneID),
	}
	data.IPProtocolScope = &IPProtocolScopeModel{
		IPVersion: types.StringValue(p.IPProtocolScope.IPVersion),
	}
	data.LoggingEnabled = types.BoolValue(p.LoggingEnabled)
	if p.IPsecFilter != "" {
		data.IPsecFilter = types.StringValue(p.IPsecFilter)
	} else {
		data.IPsecFilter = types.StringNull()
	}

	if p.Schedule != nil {
		data.Schedule = &FirewallScheduleModel{
			Mode: types.StringValue(p.Schedule.Mode),
		}

		if p.Schedule.Mode == "ONE_TIME_ONLY" {
			if p.Schedule.Start != "" {
				data.Schedule.Start = types.StringValue(p.Schedule.Start)
			}
			if p.Schedule.Stop != "" {
				data.Schedule.Stop = types.StringValue(p.Schedule.Stop)
			}
		} else if p.Schedule.Mode == "EVERY_WEEK" {
			if len(p.Schedule.RepeatOnDays) > 0 {
				days := mapDayNamesFromAPI(p.Schedule.RepeatOnDays)
				data.Schedule.DaysOfWeek, _ = types.SetValueFrom(ctx, types.StringType, days)
			}
		}
	}

	if len(p.ConnectionStateFilter) > 0 {
		data.ConnectionStateFilter, _ = types.SetValueFrom(ctx, types.StringType, p.ConnectionStateFilter)
	} else {
		data.ConnectionStateFilter = types.SetNull(types.StringType)
	}

	if p.Source.TrafficFilter != nil {
		data.Source.TrafficFilter = mapTrafficFilterFromAPI(ctx, p.Source.TrafficFilter)
	}

	if p.Destination.TrafficFilter != nil {
		data.Destination.TrafficFilter = mapTrafficFilterFromAPI(ctx, p.Destination.TrafficFilter)
	}

	if p.IPProtocolScope.ProtocolFilter != nil {
		tfType := p.IPProtocolScope.ProtocolFilter.Type
		if strings.EqualFold(tfType, "NAMED_PROTOCOL") {
			tfType = "PROTOCOL" // Reverse mapping to prevent TF diffs
		}
		data.IPProtocolScope.ProtocolFilter = &ProtocolFilterModel{
			Type:          types.StringValue(tfType),
			MatchOpposite: types.BoolValue(p.IPProtocolScope.ProtocolFilter.MatchOpposite),
		}
		if protocol := mapProtocolFromAPI(p.IPProtocolScope.ProtocolFilter.Protocol); protocol != "" {
			data.IPProtocolScope.ProtocolFilter.Protocol = types.StringValue(protocol)
		}
	}
}

// mapDayNamesFromAPI converts full day names (MONDAY) from the API to short format (MON).
func mapDayNamesFromAPI(days []string) []string {
	fullToShort := map[string]string{
		"MONDAY": "MON", "TUESDAY": "TUE", "WEDNESDAY": "WED",
		"THURSDAY": "THU", "FRIDAY": "FRI", "SATURDAY": "SAT", "SUNDAY": "SUN",
	}
	out := make([]string, len(days))
	for i, d := range days {
		if short, ok := fullToShort[d]; ok {
			out[i] = short
		} else {
			out[i] = d
		}
	}
	return out
}

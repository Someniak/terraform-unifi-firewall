package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

type FirewallPolicyResource struct {
	client *unifi.Client
}

type FirewallPolicyResourceModel struct {
	ID                    types.String          `tfsdk:"id"`
	Enabled               types.Bool            `tfsdk:"enabled"`
	Name                  types.String          `tfsdk:"name"`
	Description           types.String          `tfsdk:"description"`
	Action                *ActionModel          `tfsdk:"action"`
	Source                *SourceDestModel      `tfsdk:"source"`
	Destination           *SourceDestModel      `tfsdk:"destination"`
	IPProtocolScope       *IPProtocolScopeModel `tfsdk:"ip_protocol_scope"`
	ConnectionStateFilter types.Set             `tfsdk:"connection_state_filter"`
	LoggingEnabled        types.Bool            `tfsdk:"logging_enabled"`
}

type ActionModel struct {
	Type               types.String `tfsdk:"type"`
	AllowReturnTraffic types.Bool   `tfsdk:"allow_return_traffic"`
}

type SourceDestModel struct {
	ZoneID        types.String        `tfsdk:"zone_id"`
	TrafficFilter *TrafficFilterModel `tfsdk:"traffic_filter"`
}

type TrafficFilterModel struct {
	Type             types.String           `tfsdk:"type"`
	PortFilter       *PortFilterModel       `tfsdk:"port_filter"`
	DomainFilter     *DomainFilterModel     `tfsdk:"domain_filter"`
	IPAddressFilter  *IPAddressFilterModel  `tfsdk:"ip_address_filter"`
	MACAddressFilter *MACAddressFilterModel `tfsdk:"mac_address_filter"`
	NetworkFilter    *NetworkFilterModel    `tfsdk:"network_filter"`
	MACAddress       types.String           `tfsdk:"mac_address"`
}

type IPAddressFilterModel struct {
	Type          types.String `tfsdk:"type"`
	MatchOpposite types.Bool   `tfsdk:"match_opposite"`
	Items         types.List   `tfsdk:"items"`
}

type MACAddressFilterModel struct {
	Type          types.String `tfsdk:"type"`
	MatchOpposite types.Bool   `tfsdk:"match_opposite"`
	Items         types.List   `tfsdk:"items"`
}

type NetworkFilterModel struct {
	Type          types.String `tfsdk:"type"`
	MatchOpposite types.Bool   `tfsdk:"match_opposite"`
	Items         types.List   `tfsdk:"items"`
}

type PortFilterModel struct {
	Type          types.String    `tfsdk:"type"`
	MatchOpposite types.Bool      `tfsdk:"match_opposite"`
	Items         []PortItemModel `tfsdk:"items"`
}

type PortItemModel struct {
	Type  types.String `tfsdk:"type"`
	Value types.Int32  `tfsdk:"value"`
	Start types.Int32  `tfsdk:"start"`
	Stop  types.Int32  `tfsdk:"stop"`
}

type DomainFilterModel struct {
	Items []types.String `tfsdk:"items"`
}

type IPProtocolScopeModel struct {
	IPVersion      types.String         `tfsdk:"ip_version"`
	ProtocolFilter *ProtocolFilterModel `tfsdk:"protocol_filter"`
}

type ProtocolFilterModel struct {
	Type          types.String `tfsdk:"type"`
	Protocol      types.String `tfsdk:"protocol"`
	MatchOpposite types.Bool   `tfsdk:"match_opposite"`
}

func NewFirewallPolicyResource() resource.Resource {
	return &FirewallPolicyResource{}
}

func (r *FirewallPolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_policy"
}

func (r *FirewallPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"enabled": schema.BoolAttribute{
				Required: true,
			},
			"name": schema.StringAttribute{
				Required: true,
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"connection_state_filter": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"logging_enabled": schema.BoolAttribute{
				Required: true,
			},
		},
		Blocks: map[string]schema.Block{
			"action": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						Required: true,
						Validators: []validator.String{
							stringvalidator.OneOf("ALLOW", "BLOCK", "REJECT"),
						},
					},
					"allow_return_traffic": schema.BoolAttribute{
						Required: true,
					},
				},
			},
			"source": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"zone_id": schema.StringAttribute{
						Required: true,
					},
				},
				Blocks: map[string]schema.Block{
					"traffic_filter": schema.SingleNestedBlock{
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Required: true,
							},
							"mac_address": schema.StringAttribute{
								Optional: true,
							},
						},
						Blocks: map[string]schema.Block{
							"port_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Required: true,
									},
									"match_opposite": schema.BoolAttribute{
										Required: true,
									},
								},
								Blocks: map[string]schema.Block{
									"items": schema.ListNestedBlock{
										NestedObject: schema.NestedBlockObject{
											Attributes: map[string]schema.Attribute{
												"type": schema.StringAttribute{
													Required: true,
												},
												"value": schema.Int32Attribute{
													Optional: true,
												},
												"start": schema.Int32Attribute{
													Optional: true,
												},
												"stop": schema.Int32Attribute{
													Optional: true,
												},
											},
										},
									},
								},
							},
							"ip_address_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true,
									},
									"match_opposite": schema.BoolAttribute{
										Required: true,
									},
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Required:    true,
									},
								},
							},
							"mac_address_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true,
									},
									"match_opposite": schema.BoolAttribute{
										Required: true,
									},
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Required:    true,
									},
								},
							},
							"network_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true,
									},
									"match_opposite": schema.BoolAttribute{
										Required: true,
									},
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Required:    true,
									},
								},
							},
						},
					},
				},
			},
			"destination": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"zone_id": schema.StringAttribute{
						Required: true,
					},
				},
				Blocks: map[string]schema.Block{
					"traffic_filter": schema.SingleNestedBlock{
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Required: true,
							},
							"mac_address": schema.StringAttribute{
								Optional: true,
							},
						},
						Blocks: map[string]schema.Block{
							"port_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Required: true,
									},
									"match_opposite": schema.BoolAttribute{
										Required: true,
									},
								},
								Blocks: map[string]schema.Block{
									"items": schema.ListNestedBlock{
										NestedObject: schema.NestedBlockObject{
											Attributes: map[string]schema.Attribute{
												"type": schema.StringAttribute{
													Required: true,
												},
												"value": schema.Int32Attribute{
													Optional: true,
												},
												"start": schema.Int32Attribute{
													Optional: true,
												},
												"stop": schema.Int32Attribute{
													Optional: true,
												},
											},
										},
									},
								},
							},
							"ip_address_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true,
									},
									"match_opposite": schema.BoolAttribute{
										Required: true,
									},
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Required:    true,
									},
								},
							},
							"mac_address_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true,
									},
									"match_opposite": schema.BoolAttribute{
										Required: true,
									},
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Required:    true,
									},
								},
							},
							"network_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true,
									},
									"match_opposite": schema.BoolAttribute{
										Required: true,
									},
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Required:    true,
									},
								},
							},
							"domain_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Required:    true,
									},
								},
							},
						},
					},
				},
			},
			"ip_protocol_scope": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"ip_version": schema.StringAttribute{
						Required: true,
						Validators: []validator.String{
							stringvalidator.OneOf("IPV4", "IPV6", "IPV4_AND_IPV6"),
						},
					},
				},
				Blocks: map[string]schema.Block{
					"protocol_filter": schema.SingleNestedBlock{
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Optional: true,
							},
							"protocol": schema.StringAttribute{
								Optional: true,
							},
							"match_opposite": schema.BoolAttribute{
								Required: true,
							},
						},
					},
				},
			},
		},
	}
}
func (r *FirewallPolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*unifi.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *unifi.Client, got %T", req.ProviderData))
		return
	}

	r.client = client
}

func (r *FirewallPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data FirewallPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy := r.mapToAPI(ctx, data)

	created, err := r.client.CreateFirewallPolicy(policy)
	if err != nil {
		resp.Diagnostics.AddError("Error creating firewall policy", err.Error())
		return
	}

	data.ID = types.StringValue(created.ID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *FirewallPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data FirewallPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.client.GetFirewallPolicy(data.ID.ValueString())
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.mapFromAPI(ctx, policy, &data)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *FirewallPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state FirewallPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy := r.mapToAPI(ctx, plan)
	_, err := r.client.UpdateFirewallPolicy(state.ID.ValueString(), policy)
	if err != nil {
		resp.Diagnostics.AddError("Error updating firewall policy", err.Error())
		return
	}

	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *FirewallPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data FirewallPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteFirewallPolicy(data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error deleting firewall policy", err.Error())
		return
	}
}

func (r *FirewallPolicyResource) mapToAPI(ctx context.Context, data FirewallPolicyResourceModel) unifi.FirewallPolicy {
	policy := unifi.FirewallPolicy{
		Enabled:     data.Enabled.ValueBool(),
		Name:        data.Name.ValueString(),
		Description: data.Description.ValueString(),
		Action: unifi.FirewallAction{
			Type:               data.Action.Type.ValueString(),
			AllowReturnTraffic: data.Action.AllowReturnTraffic.ValueBool(),
		},
		Source: unifi.FirewallSourceDest{
			ZoneID: data.Source.ZoneID.ValueString(),
		},
		Destination: unifi.FirewallSourceDest{
			ZoneID: data.Destination.ZoneID.ValueString(),
		},
		IPProtocolScope: unifi.IPProtocolScope{
			IPVersion: data.IPProtocolScope.IPVersion.ValueString(),
		},
		LoggingEnabled: data.LoggingEnabled.ValueBool(),
	}

	if !data.ConnectionStateFilter.IsNull() {
		var states []string
		data.ConnectionStateFilter.ElementsAs(ctx, &states, false)
		policy.ConnectionStateFilter = states
	}

	if data.Source != nil && data.Source.TrafficFilter != nil {
		policy.Source.TrafficFilter = &unifi.TrafficFilter{
			Type: data.Source.TrafficFilter.Type.ValueString(),
		}
		if !data.Source.TrafficFilter.MACAddress.IsNull() {
			policy.Source.TrafficFilter.MACAddressFilter = data.Source.TrafficFilter.MACAddress.ValueString()
		}
		if policy.Source.TrafficFilter.Type == "" {
			policy.Source.TrafficFilter.Type = "PORT"
		}

		if data.Source.TrafficFilter.PortFilter != nil {
			policy.Source.TrafficFilter.PortFilter = &unifi.PortFilter{
				Type:          data.Source.TrafficFilter.PortFilter.Type.ValueString(),
				MatchOpposite: data.Source.TrafficFilter.PortFilter.MatchOpposite.ValueBool(),
			}
			if policy.Source.TrafficFilter.PortFilter.Type == "" {
				policy.Source.TrafficFilter.PortFilter.Type = "PORTS"
			}
			for _, item := range data.Source.TrafficFilter.PortFilter.Items {
				pi := unifi.PortItem{
					Type: item.Type.ValueString(),
				}
				if !item.Value.IsNull() {
					pi.Value = int(item.Value.ValueInt32())
				}
				if !item.Start.IsNull() {
					pi.Start = int(item.Start.ValueInt32())
				}
				if !item.Stop.IsNull() {
					pi.Stop = int(item.Stop.ValueInt32())
				}
				policy.Source.TrafficFilter.PortFilter.Items = append(policy.Source.TrafficFilter.PortFilter.Items, pi)
			}
		}

		if data.Source.TrafficFilter.IPAddressFilter != nil {
			policy.Source.TrafficFilter.IPAddressFilter = &unifi.IPAddressFilter{
				Type:          data.Source.TrafficFilter.IPAddressFilter.Type.ValueString(),
				MatchOpposite: data.Source.TrafficFilter.IPAddressFilter.MatchOpposite.ValueBool(),
			}
			if policy.Source.TrafficFilter.IPAddressFilter.Type == "" {
				policy.Source.TrafficFilter.IPAddressFilter.Type = "IP_ADDRESS"
			}

			var items []string
			data.Source.TrafficFilter.IPAddressFilter.Items.ElementsAs(ctx, &items, false)
			policy.Source.TrafficFilter.IPAddressFilter.Addresses = items
		}

		if data.Source.TrafficFilter.MACAddressFilter != nil {
			if policy.Source.TrafficFilter.MACAddressFilter == nil {
				policy.Source.TrafficFilter.MACAddressFilter = &unifi.MACAddressFilter{
					Type:          data.Source.TrafficFilter.MACAddressFilter.Type.ValueString(),
					MatchOpposite: data.Source.TrafficFilter.MACAddressFilter.MatchOpposite.ValueBool(),
				}
			}
			if macObj, ok := policy.Source.TrafficFilter.MACAddressFilter.(*unifi.MACAddressFilter); ok {
				if macObj.Type == "" {
					macObj.Type = "MAC_ADDRESSES"
				}
				var items []string
				data.Source.TrafficFilter.MACAddressFilter.Items.ElementsAs(ctx, &items, false)
				macObj.MACAddresses = items
			}

		}

		if data.Source.TrafficFilter.NetworkFilter != nil {
			policy.Source.TrafficFilter.NetworkFilter = &unifi.NetworkFilter{
				Type:          data.Source.TrafficFilter.NetworkFilter.Type.ValueString(),
				MatchOpposite: data.Source.TrafficFilter.NetworkFilter.MatchOpposite.ValueBool(),
			}
			if policy.Source.TrafficFilter.NetworkFilter.Type == "" {
				policy.Source.TrafficFilter.NetworkFilter.Type = "NETWORK"
			}

			var items []string
			data.Source.TrafficFilter.NetworkFilter.Items.ElementsAs(ctx, &items, false)
			policy.Source.TrafficFilter.NetworkFilter.NetworkIDs = items
		}
	}

	if data.Destination != nil && data.Destination.TrafficFilter != nil {
		policy.Destination.TrafficFilter = &unifi.TrafficFilter{
			Type: data.Destination.TrafficFilter.Type.ValueString(),
		}
		if !data.Destination.TrafficFilter.MACAddress.IsNull() {
			policy.Destination.TrafficFilter.MACAddressFilter = data.Destination.TrafficFilter.MACAddress.ValueString()
		}
		if policy.Destination.TrafficFilter.Type == "" {
			if data.Destination.TrafficFilter.DomainFilter != nil {
				policy.Destination.TrafficFilter.Type = "DOMAIN"
			} else {
				policy.Destination.TrafficFilter.Type = "PORT"
			}
		}

		if data.Destination.TrafficFilter.PortFilter != nil {
			policy.Destination.TrafficFilter.PortFilter = &unifi.PortFilter{
				Type:          data.Destination.TrafficFilter.PortFilter.Type.ValueString(),
				MatchOpposite: data.Destination.TrafficFilter.PortFilter.MatchOpposite.ValueBool(),
			}
			if policy.Destination.TrafficFilter.PortFilter.Type == "" {
				policy.Destination.TrafficFilter.PortFilter.Type = "PORTS"
			}
			for _, item := range data.Destination.TrafficFilter.PortFilter.Items {
				pi := unifi.PortItem{
					Type: item.Type.ValueString(),
				}
				if !item.Value.IsNull() {
					pi.Value = int(item.Value.ValueInt32())
				}
				if !item.Start.IsNull() {
					pi.Start = int(item.Start.ValueInt32())
				}
				if !item.Stop.IsNull() {
					pi.Stop = int(item.Stop.ValueInt32())
				}
				policy.Destination.TrafficFilter.PortFilter.Items = append(policy.Destination.TrafficFilter.PortFilter.Items, pi)
			}
		}

		if data.Destination.TrafficFilter.IPAddressFilter != nil {
			policy.Destination.TrafficFilter.IPAddressFilter = &unifi.IPAddressFilter{
				Type:          data.Destination.TrafficFilter.IPAddressFilter.Type.ValueString(),
				MatchOpposite: data.Destination.TrafficFilter.IPAddressFilter.MatchOpposite.ValueBool(),
			}
			if policy.Destination.TrafficFilter.IPAddressFilter.Type == "" {
				policy.Destination.TrafficFilter.IPAddressFilter.Type = "IP_ADDRESS"
			}
			var items []string
			data.Destination.TrafficFilter.IPAddressFilter.Items.ElementsAs(ctx, &items, false)
			policy.Destination.TrafficFilter.IPAddressFilter.Addresses = items
		}

		if data.Destination.TrafficFilter.MACAddressFilter != nil {
			if policy.Destination.TrafficFilter.MACAddressFilter == nil {
				policy.Destination.TrafficFilter.MACAddressFilter = &unifi.MACAddressFilter{
					Type:          data.Destination.TrafficFilter.MACAddressFilter.Type.ValueString(),
					MatchOpposite: data.Destination.TrafficFilter.MACAddressFilter.MatchOpposite.ValueBool(),
				}
			}
			if macObj, ok := policy.Destination.TrafficFilter.MACAddressFilter.(*unifi.MACAddressFilter); ok {
				if macObj.Type == "" {
					macObj.Type = "MAC_ADDRESSES"
				}
				var items []string
				data.Destination.TrafficFilter.MACAddressFilter.Items.ElementsAs(ctx, &items, false)
				macObj.MACAddresses = items
			}
		}

		if data.Destination.TrafficFilter.NetworkFilter != nil {
			policy.Destination.TrafficFilter.NetworkFilter = &unifi.NetworkFilter{
				Type:          data.Destination.TrafficFilter.NetworkFilter.Type.ValueString(),
				MatchOpposite: data.Destination.TrafficFilter.NetworkFilter.MatchOpposite.ValueBool(),
			}
			if policy.Destination.TrafficFilter.NetworkFilter.Type == "" {
				policy.Destination.TrafficFilter.NetworkFilter.Type = "NETWORK"
			}

			var items []string
			data.Destination.TrafficFilter.NetworkFilter.Items.ElementsAs(ctx, &items, false)
			policy.Destination.TrafficFilter.NetworkFilter.NetworkIDs = items
		}

		if data.Destination.TrafficFilter.DomainFilter != nil {
			policy.Destination.TrafficFilter.DomainFilter = &unifi.DomainFilter{
				Type: "DOMAINS",
			}
			for _, item := range data.Destination.TrafficFilter.DomainFilter.Items {
				policy.Destination.TrafficFilter.DomainFilter.Domains = append(policy.Destination.TrafficFilter.DomainFilter.Domains, item.ValueString())
			}
		}
	}

	if data.IPProtocolScope != nil && data.IPProtocolScope.ProtocolFilter != nil {
		policy.IPProtocolScope.ProtocolFilter = &unifi.ProtocolFilter{
			Type:          data.IPProtocolScope.ProtocolFilter.Type.ValueString(),
			MatchOpposite: data.IPProtocolScope.ProtocolFilter.MatchOpposite.ValueBool(),
		}
		if policy.IPProtocolScope.ProtocolFilter.Type == "" {
			policy.IPProtocolScope.ProtocolFilter.Type = "NAMED_PROTOCOL"
		}
		if !data.IPProtocolScope.ProtocolFilter.Protocol.IsNull() {
			policy.IPProtocolScope.ProtocolFilter.Protocol = map[string]interface{}{"name": data.IPProtocolScope.ProtocolFilter.Protocol.ValueString()}
		}
	}

	return policy
}

func (r *FirewallPolicyResource) mapFromAPI(ctx context.Context, p *unifi.FirewallPolicy, data *FirewallPolicyResourceModel) {
	data.Enabled = types.BoolValue(p.Enabled)
	data.Name = types.StringValue(p.Name)
	data.Description = types.StringValue(p.Description)
	data.Action = &ActionModel{
		Type:               types.StringValue(p.Action.Type),
		AllowReturnTraffic: types.BoolValue(p.Action.AllowReturnTraffic),
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

	if p.Source.TrafficFilter != nil {
		data.Source.TrafficFilter.Type = types.StringValue(p.Source.TrafficFilter.Type)
		if v, ok := p.Source.TrafficFilter.MACAddressFilter.(string); ok {
			data.Source.TrafficFilter.MACAddress = types.StringValue(v)
		}
	}
	if p.Destination.TrafficFilter != nil {
		data.Destination.TrafficFilter.Type = types.StringValue(p.Destination.TrafficFilter.Type)
		if v, ok := p.Destination.TrafficFilter.MACAddressFilter.(string); ok {
			data.Destination.TrafficFilter.MACAddress = types.StringValue(v)
		}
	}

	if p.Source.TrafficFilter != nil && p.Source.TrafficFilter.PortFilter != nil {
		var items []PortItemModel
		for _, item := range p.Source.TrafficFilter.PortFilter.Items {
			pi := PortItemModel{
				Type: types.StringValue(item.Type),
			}
			if item.Value != 0 {
				pi.Value = types.Int32Value(int32(item.Value))
			}
			if item.Start != 0 {
				pi.Start = types.Int32Value(int32(item.Start))
			}
			if item.Stop != 0 {
				pi.Stop = types.Int32Value(int32(item.Stop))
			}
			items = append(items, pi)
		}
		data.Source.TrafficFilter.PortFilter = &PortFilterModel{
			Type:          types.StringValue(p.Source.TrafficFilter.PortFilter.Type),
			MatchOpposite: types.BoolValue(p.Source.TrafficFilter.PortFilter.MatchOpposite),
			Items:         items,
		}
	}

	if p.Destination.TrafficFilter != nil && p.Destination.TrafficFilter.PortFilter != nil {
		var items []PortItemModel
		for _, item := range p.Destination.TrafficFilter.PortFilter.Items {
			pi := PortItemModel{
				Type: types.StringValue(item.Type),
			}
			if item.Value != 0 {
				pi.Value = types.Int32Value(int32(item.Value))
			}
			if item.Start != 0 {
				pi.Start = types.Int32Value(int32(item.Start))
			}
			if item.Stop != 0 {
				pi.Stop = types.Int32Value(int32(item.Stop))
			}
			items = append(items, pi)
		}
		data.Destination.TrafficFilter.PortFilter = &PortFilterModel{
			Type:          types.StringValue(p.Destination.TrafficFilter.PortFilter.Type),
			MatchOpposite: types.BoolValue(p.Destination.TrafficFilter.PortFilter.MatchOpposite),
			Items:         items,
		}
	}

	if p.Source.TrafficFilter != nil && p.Source.TrafficFilter.IPAddressFilter != nil {
		items, _ := types.ListValueFrom(ctx, types.StringType, p.Source.TrafficFilter.IPAddressFilter.Addresses)
		data.Source.TrafficFilter.IPAddressFilter = &IPAddressFilterModel{
			Type:          types.StringValue(p.Source.TrafficFilter.IPAddressFilter.Type),
			MatchOpposite: types.BoolValue(p.Source.TrafficFilter.IPAddressFilter.MatchOpposite),
			Items:         items,
		}
	}

	if p.Source.TrafficFilter != nil && p.Source.TrafficFilter.MACAddressFilter != nil {
		if macObj, ok := p.Source.TrafficFilter.MACAddressFilter.(*unifi.MACAddressFilter); ok {
			items, _ := types.ListValueFrom(ctx, types.StringType, macObj.MACAddresses)
			data.Source.TrafficFilter.MACAddressFilter = &MACAddressFilterModel{
				Type:          types.StringValue(macObj.Type),
				MatchOpposite: types.BoolValue(macObj.MatchOpposite),
				Items:         items,
			}
		}
	}

	if p.Source.TrafficFilter != nil && p.Source.TrafficFilter.NetworkFilter != nil {
		items, _ := types.ListValueFrom(ctx, types.StringType, p.Source.TrafficFilter.NetworkFilter.NetworkIDs)
		data.Source.TrafficFilter.NetworkFilter = &NetworkFilterModel{
			Type:          types.StringValue(p.Source.TrafficFilter.NetworkFilter.Type),
			MatchOpposite: types.BoolValue(p.Source.TrafficFilter.NetworkFilter.MatchOpposite),
			Items:         items,
		}
	}

	if p.Destination.TrafficFilter != nil && p.Destination.TrafficFilter.IPAddressFilter != nil {
		items, _ := types.ListValueFrom(ctx, types.StringType, p.Destination.TrafficFilter.IPAddressFilter.Addresses)
		data.Destination.TrafficFilter.IPAddressFilter = &IPAddressFilterModel{
			Type:          types.StringValue(p.Destination.TrafficFilter.IPAddressFilter.Type),
			MatchOpposite: types.BoolValue(p.Destination.TrafficFilter.IPAddressFilter.MatchOpposite),
			Items:         items,
		}
	}

	if p.Destination.TrafficFilter != nil && p.Destination.TrafficFilter.MACAddressFilter != nil {
		if macObj, ok := p.Destination.TrafficFilter.MACAddressFilter.(*unifi.MACAddressFilter); ok {
			items, _ := types.ListValueFrom(ctx, types.StringType, macObj.MACAddresses)
			data.Destination.TrafficFilter.MACAddressFilter = &MACAddressFilterModel{
				Type:          types.StringValue(macObj.Type),
				MatchOpposite: types.BoolValue(macObj.MatchOpposite),
				Items:         items,
			}
		}
	}

	if p.Destination.TrafficFilter != nil && p.Destination.TrafficFilter.NetworkFilter != nil {
		items, _ := types.ListValueFrom(ctx, types.StringType, p.Destination.TrafficFilter.NetworkFilter.NetworkIDs)
		data.Destination.TrafficFilter.NetworkFilter = &NetworkFilterModel{
			Type:          types.StringValue(p.Destination.TrafficFilter.NetworkFilter.Type),
			MatchOpposite: types.BoolValue(p.Destination.TrafficFilter.NetworkFilter.MatchOpposite),
			Items:         items,
		}
	}

	if len(p.ConnectionStateFilter) > 0 {
		states, _ := types.SetValueFrom(ctx, types.StringType, p.ConnectionStateFilter)
		data.ConnectionStateFilter = states
	} else {
		data.ConnectionStateFilter = types.SetNull(types.StringType)
	}
}

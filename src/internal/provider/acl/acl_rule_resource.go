package acl

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

var (
	_ resource.Resource                = &ACLRuleResource{}
	_ resource.ResourceWithConfigure   = &ACLRuleResource{}
	_ resource.ResourceWithImportState = &ACLRuleResource{}
)

type ACLRuleResource struct {
	client *unifi.Client
}

type ACLRuleResourceModel struct {
	ID                    types.String       `tfsdk:"id"`
	Type                  types.String       `tfsdk:"type"`
	Name                  types.String       `tfsdk:"name"`
	Description           types.String       `tfsdk:"description"`
	Enabled               types.Bool         `tfsdk:"enabled"`
	Action                types.String       `tfsdk:"action"`
	ProtocolFilter        types.Set          `tfsdk:"protocol_filter"`
	NetworkID             types.String       `tfsdk:"network_id"`
	EnforcingDeviceFilter *DeviceFilterModel `tfsdk:"enforcing_device_filter"`
	SourceFilter          *ACLFilterModel    `tfsdk:"source_filter"`
	DestinationFilter     *ACLFilterModel    `tfsdk:"destination_filter"`
}

type DeviceFilterModel struct {
	DeviceIDs types.Set `tfsdk:"device_ids"`
}

type ACLFilterModel struct {
	Type                 types.String `tfsdk:"type"`
	IPAddressesOrSubnets types.Set    `tfsdk:"ip_addresses_or_subnets"`
	PortFilter           types.Set    `tfsdk:"port_filter"`
	NetworkIDs           types.Set    `tfsdk:"network_ids"`
	MACAddresses         types.Set    `tfsdk:"mac_addresses"`
}

func NewACLRuleResource() resource.Resource {
	return &ACLRuleResource{}
}

func (r *ACLRuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acl_rule"
}

func (r *ACLRuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	filterBlock := schema.SingleNestedBlock{
		Attributes: map[string]schema.Attribute{
			"type": schema.StringAttribute{
				Optional: true,
			},
			"ip_addresses_or_subnets": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"port_filter": schema.SetAttribute{
				ElementType: types.Int64Type,
				Optional:    true,
			},
			"network_ids": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"mac_addresses": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
		},
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an ACL (Access Control List) rule for switch-level traffic control.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"type": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf("IPV4", "MAC"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Required: true,
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"enabled": schema.BoolAttribute{
				Required: true,
			},
			"action": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf("ALLOW", "BLOCK"),
				},
			},
			"protocol_filter": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"network_id": schema.StringAttribute{
				Optional: true,
			},
		},
		Blocks: map[string]schema.Block{
			"enforcing_device_filter": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"device_ids": schema.SetAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
				},
			},
			"source_filter":      filterBlock,
			"destination_filter": filterBlock,
		},
	}
}

func (r *ACLRuleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ACLRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ACLRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule := r.mapToAPI(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	created, err := r.client.CreateACLRule(rule)
	if err != nil {
		resp.Diagnostics.AddError("Error creating ACL rule", err.Error())
		return
	}

	plan.ID = types.StringValue(created.ID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ACLRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ACLRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, err := r.client.GetACLRule(state.ID.ValueString())
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	r.mapFromAPI(ctx, rule, &state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ACLRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ACLRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule := r.mapToAPI(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.UpdateACLRule(plan.ID.ValueString(), rule)
	if err != nil {
		resp.Diagnostics.AddError("Error updating ACL rule", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ACLRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ACLRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteACLRule(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error deleting ACL rule", err.Error())
		return
	}
}

func (r *ACLRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

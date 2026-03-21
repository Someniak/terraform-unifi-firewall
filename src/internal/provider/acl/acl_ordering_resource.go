package acl

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

var (
	_ resource.Resource              = &ACLRuleOrderingResource{}
	_ resource.ResourceWithConfigure = &ACLRuleOrderingResource{}
)

type ACLRuleOrderingResource struct {
	client *unifi.Client
}

type ACLRuleOrderingResourceModel struct {
	ID      types.String `tfsdk:"id"`
	RuleIDs types.List   `tfsdk:"rule_ids"`
}

func NewACLRuleOrderingResource() resource.Resource {
	return &ACLRuleOrderingResource{}
}

func (r *ACLRuleOrderingResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acl_ordering"
}

func (r *ACLRuleOrderingResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the ordering of user-defined ACL rules. Lower index means higher priority.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"rule_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				Required:            true,
				MarkdownDescription: "Ordered list of ACL rule IDs. First rule has highest priority.",
			},
		},
	}
}

func (r *ACLRuleOrderingResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ACLRuleOrderingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ACLRuleOrderingResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var ruleIDs []string
	resp.Diagnostics.Append(plan.RuleIDs.ElementsAs(ctx, &ruleIDs, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.UpdateACLRuleOrdering(unifi.ACLRuleOrdering{RuleIDs: ruleIDs})
	if err != nil {
		resp.Diagnostics.AddError("Error setting ACL rule ordering", err.Error())
		return
	}

	plan.ID = types.StringValue("acl-ordering")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ACLRuleOrderingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ACLRuleOrderingResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleIDs, err := r.client.GetACLRuleOrdering()
	if err != nil {
		resp.Diagnostics.AddError("Error reading ACL rule ordering", err.Error())
		return
	}

	listVal, diags := types.ListValueFrom(ctx, types.StringType, ruleIDs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.RuleIDs = listVal
	state.ID = types.StringValue("acl-ordering")
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ACLRuleOrderingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ACLRuleOrderingResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var ruleIDs []string
	resp.Diagnostics.Append(plan.RuleIDs.ElementsAs(ctx, &ruleIDs, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.UpdateACLRuleOrdering(unifi.ACLRuleOrdering{RuleIDs: ruleIDs})
	if err != nil {
		resp.Diagnostics.AddError("Error updating ACL rule ordering", err.Error())
		return
	}

	plan.ID = types.StringValue("acl-ordering")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ACLRuleOrderingResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Ordering is inherent to the system — deletion is a no-op.
}

package firewall

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

var (
	_ resource.Resource                = &DNSPolicyResource{}
	_ resource.ResourceWithConfigure   = &DNSPolicyResource{}
	_ resource.ResourceWithImportState = &DNSPolicyResource{}
)

func NewDNSPolicyResource() resource.Resource {
	return &DNSPolicyResource{}
}

type DNSPolicyResource struct {
	client *unifi.Client
}

func (r *DNSPolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dns"
}

func (r *DNSPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of the DNS policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"site_id": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The ID of the site.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The type of DNS policy (e.g., A_RECORD, AAAA_RECORD, CNAME_RECORD, MX_RECORD, TXT_RECORD, SRV_RECORD, FORWARD_DOMAIN).",
			},
			"domain": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The domain name for the policy.",
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Whether the policy is enabled.",
			},
			"ip_address": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The IP address for A records (IPv4), AAAA records (IPv6), or FORWARD_DOMAIN (DNS server IP).",
			},
			"cname": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The target domain for CNAME records.",
			},
			"mail_server": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The mail server domain for MX records.",
			},
			"priority": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "The priority for MX or SRV records.",
			},
			"server_domain": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The server domain for SRV records.",
			},
			"service": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The service name for SRV records (e.g., _ldap).",
			},
			"protocol": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The protocol for SRV records (e.g., _tcp).",
			},
			"weight": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "The weight for SRV records.",
			},
			"port": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "The port for SRV records.",
			},
			"text": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The text content for TXT records.",
			},
			"ttl": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				// Default:             int64default.StaticInt64(300), // Could set a default, but API might have its own.
				MarkdownDescription: "The TTL in seconds.",
			},
		},
	}
}

func (r *DNSPolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*unifi.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *unifi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

// effectiveSiteID returns the site ID to use for DNS API calls. Always uses
// the provider-level discovered site ID to avoid stale values from state.
func (r *DNSPolicyResource) effectiveSiteID(_ types.String) string {
	return r.client.SiteID
}

func (r *DNSPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan DNSPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Prepare API request
	policy := unifi.DNSPolicy{
		Type:    plan.Type.ValueString(),
		Domain:  plan.Domain.ValueString(),
		Enabled: plan.Enabled.ValueBool(),
	}

	if !plan.IPAddress.IsNull() {
		switch policy.Type {
		case "A_RECORD":
			policy.IPv4Address = plan.IPAddress.ValueString()
		case "AAAA_RECORD":
			policy.IPv6Address = plan.IPAddress.ValueString()
		case "FORWARD_DOMAIN":
			policy.IPAddress = plan.IPAddress.ValueString()
		}
	}
	if !plan.CNAME.IsNull() {
		policy.TargetDomain = plan.CNAME.ValueString()
	}
	if !plan.MailServer.IsNull() {
		policy.MailServerDomain = plan.MailServer.ValueString()
	}
	if !plan.Priority.IsNull() {
		policy.Priority = int(plan.Priority.ValueInt64())
	}
	if !plan.ServerDomain.IsNull() {
		policy.ServerDomain = plan.ServerDomain.ValueString()
	}
	if !plan.Service.IsNull() {
		policy.Service = plan.Service.ValueString()
	}
	if !plan.Protocol.IsNull() {
		policy.Protocol = plan.Protocol.ValueString()
	}
	if !plan.Weight.IsNull() {
		policy.Weight = int(plan.Weight.ValueInt64())
	}
	if !plan.Port.IsNull() {
		policy.Port = int(plan.Port.ValueInt64())
	}
	if !plan.Text.IsNull() {
		policy.Text = plan.Text.ValueString()
	}
	if !plan.TTL.IsNull() {
		policy.TTL = int(plan.TTL.ValueInt64())
	}

	siteID := r.effectiveSiteID(plan.SiteID)

	createdPolicy, err := r.client.CreateDNSPolicy(siteID, policy)
	if err != nil {
		resp.Diagnostics.AddError("Error creating DNS policy", err.Error())
		return
	}

	plan.ID = types.StringValue(createdPolicy.ID)
	plan.SiteID = types.StringValue(siteID)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DNSPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state DNSPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	siteID := r.effectiveSiteID(state.SiteID)

	policy, err := r.client.GetDNSPolicy(siteID, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading DNS policy", err.Error())
		return
	}

	// Update state
	state.Type = types.StringValue(policy.Type)
	state.Domain = types.StringValue(policy.Domain)
	state.Enabled = types.BoolValue(policy.Enabled)

	switch policy.Type {
	case "A_RECORD":
		if policy.IPv4Address != "" {
			state.IPAddress = types.StringValue(policy.IPv4Address)
		}
	case "AAAA_RECORD":
		if policy.IPv6Address != "" {
			state.IPAddress = types.StringValue(policy.IPv6Address)
		}
	case "FORWARD_DOMAIN":
		if policy.IPAddress != "" {
			state.IPAddress = types.StringValue(policy.IPAddress)
		}
	}

	if policy.TargetDomain != "" {
		state.CNAME = types.StringValue(policy.TargetDomain)
	}
	if policy.MailServerDomain != "" {
		state.MailServer = types.StringValue(policy.MailServerDomain)
	}
	if policy.Priority != 0 {
		state.Priority = types.Int64Value(int64(policy.Priority))
	}
	if policy.ServerDomain != "" {
		state.ServerDomain = types.StringValue(policy.ServerDomain)
	}
	if policy.Service != "" {
		state.Service = types.StringValue(policy.Service)
	}
	if policy.Protocol != "" {
		state.Protocol = types.StringValue(policy.Protocol)
	}
	if policy.Weight != 0 {
		state.Weight = types.Int64Value(int64(policy.Weight))
	}
	if policy.Port != 0 {
		state.Port = types.Int64Value(int64(policy.Port))
	}
	if policy.Text != "" {
		state.Text = types.StringValue(policy.Text)
	}
	if policy.TTL != 0 {
		state.TTL = types.Int64Value(int64(policy.TTL))
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *DNSPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan DNSPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy := unifi.DNSPolicy{
		ID:      plan.ID.ValueString(),
		Type:    plan.Type.ValueString(),
		Domain:  plan.Domain.ValueString(),
		Enabled: plan.Enabled.ValueBool(),
	}

	if !plan.IPAddress.IsNull() {
		switch policy.Type {
		case "A_RECORD":
			policy.IPv4Address = plan.IPAddress.ValueString()
		case "AAAA_RECORD":
			policy.IPv6Address = plan.IPAddress.ValueString()
		case "FORWARD_DOMAIN":
			policy.IPAddress = plan.IPAddress.ValueString()
		}
	}
	if !plan.CNAME.IsNull() {
		policy.TargetDomain = plan.CNAME.ValueString()
	}
	if !plan.MailServer.IsNull() {
		policy.MailServerDomain = plan.MailServer.ValueString()
	}
	if !plan.Priority.IsNull() {
		policy.Priority = int(plan.Priority.ValueInt64())
	}
	if !plan.ServerDomain.IsNull() {
		policy.ServerDomain = plan.ServerDomain.ValueString()
	}
	if !plan.Service.IsNull() {
		policy.Service = plan.Service.ValueString()
	}
	if !plan.Protocol.IsNull() {
		policy.Protocol = plan.Protocol.ValueString()
	}
	if !plan.Weight.IsNull() {
		policy.Weight = int(plan.Weight.ValueInt64())
	}
	if !plan.Port.IsNull() {
		policy.Port = int(plan.Port.ValueInt64())
	}
	if !plan.Text.IsNull() {
		policy.Text = plan.Text.ValueString()
	}
	if !plan.TTL.IsNull() {
		policy.TTL = int(plan.TTL.ValueInt64())
	}

	siteID := r.effectiveSiteID(plan.SiteID)

	_, err := r.client.UpdateDNSPolicy(siteID, plan.ID.ValueString(), policy)
	if err != nil {
		resp.Diagnostics.AddError("Error updating DNS policy", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DNSPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state DNSPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	siteID := r.effectiveSiteID(state.SiteID)

	err := r.client.DeleteDNSPolicy(siteID, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error deleting DNS policy", err.Error())
		return
	}
}

func (r *DNSPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

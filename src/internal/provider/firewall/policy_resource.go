package firewall

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

type FirewallPolicyResource struct {
	client *unifi.Client
}

func NewFirewallPolicyResource() resource.Resource {
	return &FirewallPolicyResource{}
}

func (r *FirewallPolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_policy"
}

func (r *FirewallPolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*unifi.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", "Expected *unifi.Client")
		return
	}

	r.client = client
}

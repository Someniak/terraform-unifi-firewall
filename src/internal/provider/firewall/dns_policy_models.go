package firewall

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type DNSPolicyResourceModel struct {
	ID      types.String `tfsdk:"id"`
	SiteID  types.String `tfsdk:"site_id"`
	Type    types.String `tfsdk:"type"`
	Domain  types.String `tfsdk:"domain"`
	Enabled types.Bool   `tfsdk:"enabled"`

	// A_RECORD, AAAA_RECORD, FORWARD_DOMAIN
	IPAddress types.String `tfsdk:"ip_address"`
	// CNAME_RECORD
	CNAME types.String `tfsdk:"cname"`
	// MX_RECORD
	MailServer types.String `tfsdk:"mail_server"`
	// MX_RECORD, SRV_RECORD
	Priority types.Int64 `tfsdk:"priority"`
	// SRV_RECORD
	ServerDomain types.String `tfsdk:"server_domain"`
	Service      types.String `tfsdk:"service"`
	Protocol     types.String `tfsdk:"protocol"`
	Weight       types.Int64  `tfsdk:"weight"`
	Port         types.Int64  `tfsdk:"port"`
	// TXT_RECORD
	Text types.String `tfsdk:"text"`
	// Common
	TTL types.Int64 `tfsdk:"ttl"`
}

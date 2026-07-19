package fixedip

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type FixedIPResourceModel struct {
	ID        types.String `tfsdk:"id"`
	MAC       types.String `tfsdk:"mac"`
	NetworkID types.String `tfsdk:"network_id"`
	FixedIP   types.String `tfsdk:"fixed_ip"`
	Name      types.String `tfsdk:"name"`
	// CreatedByProvider is true when the provider had to create the underlying
	// known-client record (the MAC was not already known to the controller).
	// Delete uses this to decide between fully forgetting the record and merely
	// clearing the reservation on a pre-existing device.
	CreatedByProvider types.Bool `tfsdk:"created_by_provider"`
}

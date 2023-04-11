package nixos

import (
	"context"

	"mtoohey.com/terraform-provider-nixos/version"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// New is a helper function to simplify provider server and testing
// implementation.
func New() provider.Provider {
	return &nixOSProvider{}
}

// nixOSProvider is the provider implementation.
type nixOSProvider struct{}

// Metadata returns the provider type name.
func (p *nixOSProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "nixos"
	resp.Version = version.Version
}

// Schema defines the provider-level schema for configuration data.
func (p *nixOSProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

// Configure prepares connections for data sources and resources.
func (p *nixOSProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	// TODO: validate that the host has nix installed and that it is new enough
	// to run all the commands we need
}

// DataSources defines the data sources implemented in the provider.
func (p *nixOSProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

// Resources defines the resources implemented in the provider.
func (p *nixOSProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewNixOSHostResource}
}

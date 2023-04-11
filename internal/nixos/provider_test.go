package nixos

import (
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// providerConfig is a shared configuration to combine with the actual test
// configuration so the NixOS client is properly configured.
const providerConfig = `provider "nixos" {}
`

// testAccProtoV6ProviderFactories are used to instantiate a provider during
// acceptance testing. The factory function will be invoked for every Terraform
// CLI command executed to create a provider server to which the CLI can
// reattach.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"nixos": providerserver.NewProtocol6WithError(New()),
}

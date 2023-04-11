package main

import (
	"context"

	"mtoohey.com/terraform-provider-nixos/internal/nixos"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

func main() {
	providerserver.Serve(context.Background(), nixos.New, providerserver.ServeOpts{
		Address: "mtoohey.com/nix/nixos",
	})
}

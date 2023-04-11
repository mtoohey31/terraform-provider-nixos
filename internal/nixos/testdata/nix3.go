package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

func main() {
	switch strings.Join(os.Args[1:], " ") {
	case "build --out-link .terraform-provider-nixos/test-machine-id path/to/other/flake#nixosConfigurations.other.flake.attr.config.system.build.toplevel":
		if err := os.Remove(".terraform-provider-nixos/test-machine-id"); err != nil && !errors.Is(err, os.ErrNotExist) {
			panic(err)
		}
		if err := os.Symlink("/nix/store/third-profile-path", ".terraform-provider-nixos/test-machine-id"); err != nil {
			panic(err)
		}

	case "copy --to ssh://test-username@127.0.0.1 /nix/store/third-profile-path":

	case "show-derivation path/to/other/flake#nixosConfigurations.other.flake.attr.config.system.build.toplevel":
		fmt.Println(`{
  "/nix/store/other-profile-derivation.drv": {
    "outputs": {
      "out": {
        "path": "/nix/store/third-profile-path"
      }
    }
  }
}`)

	default:
		panic(strings.Join(os.Args[1:], " "))
	}
}

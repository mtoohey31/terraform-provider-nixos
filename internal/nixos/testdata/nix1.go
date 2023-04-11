package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

func main() {
	switch strings.Join(os.Args[1:], " ") {
	case "build --out-link .terraform-provider-nixos/test-machine-id path/to/test/flake#nixosConfigurations.test.flake.attr.config.system.build.toplevel":
		if err := os.Remove(".terraform-provider-nixos/test-machine-id"); err != nil && !errors.Is(err, os.ErrNotExist) {
			panic(err)
		}
		if err := os.Symlink("/nix/store/test-profile-path", ".terraform-provider-nixos/test-machine-id"); err != nil {
			panic(err)
		}

	case "copy --to ssh://test-username@127.0.0.1 /nix/store/test-profile-path":

	case "show-derivation path/to/test/flake#nixosConfigurations.test.flake.attr.config.system.build.toplevel":
		fmt.Println(`{
  "/nix/store/test-profile-derivation.drv": {
    "outputs": {
      "out": {
        "path": "/nix/store/test-profile-path"
      }
    }
  }
}`)

	default:
		panic(strings.Join(os.Args[1:], " "))
	}
}

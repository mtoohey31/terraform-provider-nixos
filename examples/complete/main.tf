terraform {
  required_providers {
    nixos = {
      source  = "mtoohey.com/nix/nixos"
      version = "0.1.0"
    }
  }
}

provider "nixos" {}

resource "nixos_host" "complete" {
  flake_ref = pathexpand("~/path/to/flake#complete")

  # user must have permission to change the system profile
  username         = "complete"
  host             = "complete.example.com"
  port             = 23712
  public_key       = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
  private_key_path = pathexpand("~/.ssh/id_ed25519")
}

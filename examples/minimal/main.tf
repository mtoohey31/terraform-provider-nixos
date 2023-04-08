terraform {
  required_providers {
    nixos = {
      source  = "mtoohey.com/nix/nixos"
      version = "0.1.0"
    }
  }
}

provider "nixos" {}

resource "nixos_host" "minimal" {
  # user must have permission to change the system profile
  username         = "minimal"
  host             = "minimal.example.com"
  public_key       = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
  private_key_path = pathexpand("~/.ssh/id_ed25519")
}

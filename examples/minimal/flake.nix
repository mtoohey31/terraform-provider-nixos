{
  description = "terraform-provider-nixos-minimal-example";

  inputs.nixpkgs.url = "nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }: {
    nixosConfigurations.minimal = nixpkgs.lib.nixosSystem {
      modules = [{
        boot.loader.systemd-boot.enable = true;
        fileSystems."/" = {
          device = "/dev/disk/by-uuid/1cb268eb-f849-4789-90a0-138af72c8291";
          fsType = "ext4";
        };
        system.stateVersion = "23.05";
      }];
      system = "x86_64-linux";
    };
  };
}

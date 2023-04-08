{
  description = "terraform-provider-nixos";

  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }: {
    overlays.default = final: _: {
      terraform-provider-nixos = final.buildGoModule {
        pname = "terraform-provider-nixos";
        version = builtins.readFile version/version.txt;
        src = ./.;
        vendorSha256 = null;
      };
    };
  } // utils.lib.eachDefaultSystem (system: with import nixpkgs
    {
      overlays = [
        (final: _: {
          gow = final.buildGoModule rec {
            pname = "gow";
            version = builtins.substring 0 7 src.rev;
            src = final.fetchFromGitHub {
              owner = "mitranim";
              repo = pname;
              rev = "a5bfab26a0e42ee646f0969ac3397e80e5e3b1df";
              sha256 = "vlIbVoAxeeQ1SB8FmSAfQ35fX6f+/VGZmrPDdA3HTvs=";
            };
            vendorSha256 = "o6KltbjmAN2w9LMeS9oozB0qz9tSMYmdDW3CwUNChzA=";
          };
        })
        self.overlays.default
      ]; inherit system;
    }; {
    packages.default = terraform-provider-nixos;

    devShells.default = mkShell {
      packages = [ go gopls gow terraform terraform-ls ];
    };
  });
}

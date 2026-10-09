# M7-07: Nix flake (SPEC §20).
#
#   nix build .#sverb            # the client (with sync), man page and completions
#   nix build .#sverb-server     # the sync server
#   nix run github:viperh/sverb  # run without installing
#   nix develop                  # toolchain for hacking on sverb
#
# CI runs `nix build .#sverb` (ci.yml, job `nix`). Cargo.lock has no git dependencies,
# so `cargoLock.lockFile` needs no output hashes.
{
  description = "sverb: a terminal-native SSH client and server manager";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = pkgs.lib;
        manifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        version = manifest.workspace.package.version;
        src = lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let base = baseNameOf path; in
            !(builtins.elem base [ "target" ".git" ".merge" ".sverb-home" "result" ]);
        };
        common = {
          inherit version src;
          cargoLock.lockFile = ./Cargo.lock;
          # Most tests need a PTY, loopback sockets or Docker; CI runs them.
          doCheck = false;
          meta = {
            homepage = "https://github.com/viperh/sverb";
            license = lib.licenses.mit;
            platforms = lib.platforms.unix;
          };
        };
      in
      {
        packages = rec {
          sverb = pkgs.rustPlatform.buildRustPackage (common // {
            pname = "sverb";
            cargoBuildFlags = [ "-p" "sverb" ];
            nativeBuildInputs = [ pkgs.installShellFiles ];
            postInstall = ''
              export SVERB_HOME="$TMPDIR/sverb-home" SVERB_KEYRING=off
              $out/bin/sverb generate man --out-dir man
              installManPage man/sverb.1
              installShellCompletion --cmd sverb \
                --bash <($out/bin/sverb generate completions bash) \
                --zsh <($out/bin/sverb generate completions zsh) \
                --fish <($out/bin/sverb generate completions fish)
            '';
            meta = common.meta // {
              description = "Terminal-native SSH client and server manager with an encrypted vault";
              mainProgram = "sverb";
            };
          });
          sverb-server = pkgs.rustPlatform.buildRustPackage (common // {
            pname = "sverb-server";
            cargoBuildFlags = [ "-p" "sverb-server" ];
            meta = common.meta // {
              description = "Self-hosted, end-to-end-encrypted sync server for sverb";
              mainProgram = "sverb-server";
              platforms = lib.platforms.linux ++ lib.platforms.darwin;
            };
          });
          default = sverb;
        };

        apps.default = flake-utils.lib.mkApp { drv = self.packages.${system}.sverb; };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.sverb ];
          packages = with pkgs; [ cargo rustc clippy rustfmt rust-analyzer python3 ];
          SVERB_KEYRING = "off";
        };
      });
}

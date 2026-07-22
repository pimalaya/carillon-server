{
  buildFeatures ? [ ],
  buildNoDefaultFeatures ? false,
  # Passed by the shared pimalaya helper (default.nix). The server ships no
  # shell completions or man pages, so these are accepted but unused.
  buildPackages,
  installManPages ? false,
  installShellCompletions ? false,
  fetchFromGitHub,
  lib,
  rustPlatform,
  pkg-config,
  stdenv,
}:

let
  version = "0.0.1";

in
rustPlatform.buildRustPackage {
  inherit version buildNoDefaultFeatures buildFeatures;

  pname = "carillon-server";
  cargoHash = "";

  src = fetchFromGitHub {
    hash = "";
    owner = "pimalaya";
    repo = "carillon-server";
    rev = "v${version}";
  };

  nativeBuildInputs = [ pkg-config ];

  doCheck = false;

  meta = {
    description = "Carillon watch server: holds IMAP IDLE and emits content-free webhooks";
    mainProgram = "carillon-server";
    homepage = "https://github.com/pimalaya/carillon-server";
    license = with lib.licenses; [ mit asl20 ];
    maintainers = with lib.maintainers; [ soywod ];
  };
}

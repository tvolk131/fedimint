{
  lib,
  stdenv,
  Security,
  fetchFromGitHub,
  rustPlatform,
}:
rustPlatform.buildRustPackage {
  pname = "vss";
  version = "2024.12.17";

  src = fetchFromGitHub {
    owner = "G8XSU";
    repo = "vss-server";
    rev = "96290a3433b674d5554fbd69d1272740ad46aa4d";
    hash = "sha256-VTM6x8cVVFRSYbBDIzRd2PWaPvGXWXPkZ4NWxWNDzBI=";
  };

  sourceRoot = "source/rust";

  cargoHash = "sha256-HAy9No+9tG6jAWYB/T8UfODuBVsQ9hw3JSAjypkKOEg=";

  buildInputs = lib.optionals stdenv.isDarwin [ Security ];
}

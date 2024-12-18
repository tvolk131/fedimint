final: prev: {
  vss = prev.callPackage ../pkgs/vss.nix {
    inherit (prev.darwin.apple_sdk.frameworks) Security;
  };
}

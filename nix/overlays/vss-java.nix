final: prev: {
  buildGradleApplication = import ((builtins.fetchGit {
    url = "https://github.com/raphiz/buildGradleApplication.git";
    rev = "6392bb66587d5476c212e3ebbe19850226d2d350";
    allRefs = true;
  }) + "/buildGradleApplication") {
    pkgs = final;
    inherit (prev) lib stdenvNoCC writeShellScript makeWrapper;
    mkM2Repository = { pname, version, src, repositories ? [], dependencyFilter ? null, verificationFile ? null }:
      prev.stdenv.mkDerivation {
        inherit pname version src;

        name = "${pname}-${version}-m2-repository";

        buildCommand = ''
          mkdir -p $out/repository
        '';

        dontUnpack = true;
        dontConfigure = true;
        dontBuild = true;
        dontInstall = true;

        passthru = {
          m2Repository = "$out/repository";
          dependencies = [];
        };
      };
  };

  vss-java = final.buildGradleApplication {
    pname = "vss.java";
    version = "unstable-2024-12-06";

    src = let
      fullRepo = prev.fetchgit {
        url    = "https://github.com/lightningdevkit/vss-server.git";
        rev    = "f958e1f685254b0106ba62624027abd06efda9ef";
        sha256 = "sha256-QRcuhXayszgLvHwQ0Xg6P9/UQdbsweiTSdZfzd7Wocg=";
      };
    in prev.runCommand "vss-java-source" {} ''
      mkdir -p $out
      cp -r ${fullRepo}/java/app/* $out/
    '';

    repositories = [
      "https://plugins.gradle.org/m2/"
      "https://repo1.maven.org/maven2/"
    ];

    meta = with prev.lib; {
      description = "VSS Java Server";
    };
  };
}

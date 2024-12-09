final: prev: {
  vss-java = prev.stdenv.mkDerivation {
    pname = "vss-java";
    version = "unstable-2024-12-06";

    src = prev.fetchgit {
      url    = "https://github.com/lightningdevkit/vss-server.git";
      rev    = "f958e1f685254b0106ba62624027abd06efda9ef";
      sha256 = "sha256-QRcuhXayszgLvHwQ0Xg6P9/UQdbsweiTSdZfzd7Wocg=";
    };

    nativeBuildInputs = [
      prev.openjdk
      prev.gradle
    ];
    buildInputs = [ prev.postgresql ];

    # Insert a settings.gradle file if it doesn't exist:
    patchPhase = ''
        cd java

        if [ ! -f settings.gradle ] && [ ! -f settings.gradle.kts ]; then
        cat > settings.gradle <<EOF
        pluginManagement {
            repositories {
                gradlePluginPortal()
                mavenCentral()
            }
        }
        EOF
        fi
    '';

    # Run the Gradle build
    buildPhase = ''
      gradle build
    '';

    # Install the resulting .jar files
    installPhase = ''
      mkdir -p $out/bin
      # Adjust the path if the jar ends up in a different location
      cp build/libs/*.jar $out/bin/
    '';
  };
}

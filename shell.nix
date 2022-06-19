{ pkgs ? import <nixpkgs> {config.android_sdk.accept_license = true;} }:

(pkgs.buildFHSUserEnv {
  name = "android-sdk-env";
  targetPkgs = pkgs: (with pkgs;
    [
      androidsdk_9_0
      glibc
      openjdk
    ]);
  # runScript = "bash";
  profile = ''
    # export GRADLE_OPTS="-Dorg.gradle.project.android.aapt2FromMavenOverride=${pkgs.androidsdk_9_0}/libexec/android-sdk/build-tools/28.0.3/aapt2 -Dorg.gradle.project.android.aaptFromMavenOverride=${pkgs.androidsdk_9_0}/libexec/android-sdk/build-tools/28.0.3/aapt"
    export ANDROID_HOME="''${HOME}/Android/Sdk/"
    export ANDROID_NDK_HOME="''${HOME}/Android/Sdk/"
  '';
}).env

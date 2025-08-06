{
  description = "ESP32 Mesh Network - Protest Information Node";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    arduino-nix.url = "github:bouk/arduino-nix";
    
    # Arduino package indexes
    arduino-index = {
      url = "https://downloads.arduino.cc/packages/package_index.json";
      flake = false;
    };
    esp32-index = {
      url = "https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json";
      flake = false;
    };
    library-index = {
      url = "https://downloads.arduino.cc/libraries/library_index.json";
      flake = false;
    };
    
    # TFT_eSPI library source
    tft-espi = {
      url = "github:Bodmer/TFT_eSPI";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, arduino-nix, arduino-index, esp32-index, library-index, tft-espi }:
    let
      overlays = [
        arduino-nix.overlay
        (arduino-nix.mkArduinoPackageOverlay arduino-index)
        (arduino-nix.mkArduinoPackageOverlay esp32-index)
        (arduino-nix.mkArduinoLibraryOverlay library-index)
        (final: prev: {
          custom-tft-espi = final.stdenv.mkDerivation {
            name = "TFT_eSPI";
            src = tft-espi;
            installPhase = ''
              mkdir -p $out/libraries/TFT_eSPI
              cp -r . $out/libraries/TFT_eSPI/
            '';
          };
        })
      ];
    in
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = overlays;
        };
      in {
        devShells.default = pkgs.mkShell {
          name = "esp32mesh-arduino";
          buildInputs = with pkgs; [
            (wrapArduinoCLI {
              packages = with arduinoPackages; [
                platforms.esp32.esp32."3.3.0"
              ];
              
              libraries = [
                custom-tft-espi
              ];
            })
            
            picocom
            python3
          ];
        };
      });
}

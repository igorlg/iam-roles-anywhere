# IAM Roles Anywhere CDK - Nix Package
#
# Builds the TypeScript CDK application using buildNpmPackage.
# Lambda handlers are pre-bundled with esbuild at build time.
#
# Returns: { packages.${system}, devShellPackages.${system} }
{ inputs, supportedSystems }:
let
  inherit (inputs.nixpkgs) lib;
  forAllSystems = lib.genAttrs supportedSystems;
in
{
  packages = forAllSystems (
    system:
    let
      pkgs = inputs.nixpkgs.legacyPackages.${system};
    in
    {
      iam-ra-cdk = pkgs.buildNpmPackage {
        pname = "iam-ra-cdk";
        version = "0.1.0";

        src = ./..;

        # Hash of npm dependencies from package-lock.json.
        # To update: run `nix build .#iam-ra-cdk` with empty string,
        # Nix will report the correct hash in the error message.
        npmDepsHash = "sha256-haaJY1taw+0NMCOmK6c0BZsClSc2tcNNZ9PYWkrtdUc=";

        # Don't run npm install scripts (esbuild downloads binaries)
        # We use nixpkgs esbuild instead
        npmFlags = [ "--ignore-scripts" ];

        nativeBuildInputs = [ pkgs.makeWrapper pkgs.esbuild ];

        # Build TypeScript CDK app + bundle Lambda handlers
        buildPhase = ''
          runHook preBuild
          
          # Compile CDK TypeScript
          npm run build
          
          # Bundle Lambda handlers with esbuild (pre-bundled for deployment)
          mkdir -p dist/bundled-lambdas/ca-generator
          mkdir -p dist/bundled-lambdas/cert-issuer
          
          esbuild lib/lambdas/ca-generator.ts \
            --bundle \
            --platform=node \
            --target=node20 \
            --minify \
            --outfile=dist/bundled-lambdas/ca-generator/index.js
            
          esbuild lib/lambdas/cert-issuer.ts \
            --bundle \
            --platform=node \
            --target=node20 \
            --minify \
            --outfile=dist/bundled-lambdas/cert-issuer/index.js
          
          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall

          mkdir -p $out/lib/iam-ra-cdk
          mkdir -p $out/bin

          # Copy compiled CDK app
          cp -r dist/lib/ $out/lib/iam-ra-cdk/lib/
          cp -r dist/bin/ $out/lib/iam-ra-cdk/bin/
          
          # Copy pre-bundled Lambda handlers
          cp -r dist/bundled-lambdas/ $out/lib/iam-ra-cdk/bundled-lambdas/

          # Copy config files
          cp package.json $out/lib/iam-ra-cdk/
          cp cdk.json $out/lib/iam-ra-cdk/
          cp -r node_modules $out/lib/iam-ra-cdk/

          # Create wrapper that sets LAMBDA_BUNDLE_PATH for pre-bundled lambdas
          makeWrapper $out/lib/iam-ra-cdk/node_modules/.bin/cdk $out/bin/iam-ra-cdk \
            --add-flags "--app 'node $out/lib/iam-ra-cdk/bin/iam-ra-cdk.js'" \
            --set NODE_PATH "$out/lib/iam-ra-cdk/node_modules" \
            --set LAMBDA_BUNDLE_PATH "$out/lib/iam-ra-cdk/bundled-lambdas" \
            --chdir "$out/lib/iam-ra-cdk"

          runHook postInstall
        '';

        meta = with lib; {
          description = "IAM Roles Anywhere CDK infrastructure";
          mainProgram = "iam-ra-cdk";
        };
      };
    }
  );

  devShellPackages = forAllSystems (
    system:
    let
      pkgs = inputs.nixpkgs.legacyPackages.${system};
    in
    [
      pkgs.nodejs_22
      pkgs.nodePackages.aws-cdk
      pkgs.nodePackages.typescript
      pkgs.nodePackages.typescript-language-server
      pkgs.esbuild
    ]
  );
}

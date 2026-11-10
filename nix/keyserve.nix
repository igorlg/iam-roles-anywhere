# FIFO key server for keyRef wrapper scripts (see keyserve.py and
# mkCredentialProcessScript in lib.nix).
{ writeScript, python3 }:

# Keep the Nix interpreter, never /usr/bin/env python3: keyserve relies on
# getppid(), and the macOS xcrun python3 shim adds a parent process.
writeScript "iam-ra-keyserve" ''
  #!${python3.interpreter} -I
  ${builtins.readFile ./keyserve.py}
''

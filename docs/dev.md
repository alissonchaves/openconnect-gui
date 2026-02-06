### Compilation & package preparation

Hints related to command line compilation and package preparation
on various systems are to be found in [.gitlab-ci.yml](../.gitlab-ci.yml).

In essence what is needed to compile are:

 1. Download dependencies by running:

    contrib/build_deps_mingw@msys2.sh

 2. Build the application by running:

    contrib/build_mingw@msys2.sh

 3. The generated binaries are in the build directory

### macOS dev run (Homebrew Qt)

On macOS, the build app bundle may include bundled Qt frameworks from
release packaging, which can conflict with Homebrew Qt during local runs.
If you see duplicate Qt classes or the `cocoa` platform plugin error,
remove bundled Qt from the dev app bundle:

```
./scripts/macos-dev-unbundle.sh
```

Then run:

```
/Users/alissonchaves/github/openconnect-gui/build/bin/OpenConnect-GUI.app/Contents/MacOS/OpenConnect-GUI
```

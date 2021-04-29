# citl-static-analyzer

Fast binary hardening analysis tooling.

## Building on Linux

The build process varies by Linux distribution, owing to differences between
package names and default environment configuration. Luckily, the build process
follows the same template on all supported Linux distributions:

0. Identify which Linux distribution you're using.
1. Install dependencies.
2. Decide between performing a `Release` or `Debug` build.
3. Depending on your Linux distribution, determine any additional flags which will later be passed to `cmake` (examples provided in the subsections below).
4. Follow the build instructions at the end of this section.
5. Depending on your Linux distribution, generate a package (examples provided in the subsections below).


### Arch Linux

The build dependencies can be installed with:

```bash
pacman -S git cmake clang openssl python
```

When performing the build, pass these additional flags to `cmake`:

```
-DCMAKE_CXX_COMPILER=`which clang++` -DCMAKE_C_COMPILER=`which clang`
```

### Ubuntu 14.04 LTS

The build dependencies can be installed with:

```bash
sudo apt-get install git cmake3 clang-3.9 libc++-dev libc++abi-dev libssl-dev
```

When performing the build, pass these additional flags to `cmake`:

```bash
-DCMAKE_CXX_FLAGS="-Doffsetof=__builtin_offsetof" -DCMAKE_CXX_COMPILER=`which clang++-3.9` -DCMAKE_C_COMPILER=`which clang-3.9`
```

To create a `.deb` package, perform the build using the instructions below. Then, within the build directory (i.e. `build/Release`), execute

```bash
cpack -G DEB
```

### Ubuntu 16.04 LTS

The build dependencies can be installed with:

```bash
sudo apt-get install git cmake clang-3.9 libc++-dev libc++abi-dev libssl-dev
```

When performing the build, pass these additional flags to `cmake`:

```
-DCMAKE_CXX_FLAGS="-Doffsetof=__builtin_offsetof" -DCMAKE_CXX_COMPILER=`which clang++-3.9` -DCMAKE_C_COMPILER=`which clang-3.9`
```

To create a `.deb` package, perform the build using the instructions below. Then, within the build directory (i.e. `build/Release`), execute

```bash
cpack -G DEB
```

### Ubuntu 18.04 LTS

The build dependencies for 18.04 are pretty similar to 14.04 LTS. The cmake package is now cmake v3.x and should be installed as simple cmake.

```bash
sudo apt-get install git cmake clang-3.9 libc++-dev libc++abi-dev libssl-dev
```

When performing the build, pass these additional flags to `cmake`:

```
-DCMAKE_CXX_COMPILER=`which clang++-3.9` -DCMAKE_C_COMPILER=`which clang-3.9`
```

To create a `.deb` package, perform the build using the instructions below. Then, within the build directory (i.e. `build/Release`), execute

```bash
cpack -G DEB
```

### Centos 7.3

The build dependencies can be installed with:

```bash
sudo yum groupinstall 'Development Tools'
sudo yum install git cmake3 clang openssl-dev
```

When performing the build, use the `cmake3` command instead of the `cmake`
command, and pass these additional flags to `cmake3`:

```
-DCMAKE_CXX_FLAGS="-Doffsetof=__builtin_offsetof" -DCMAKE_CXX_COMPILER=`which clang++` -DCMAKE_C_COMPILER=`which clang`
```

To create a `.rpm` package, perform the build using the instructions below. Then, within the build directory (i.e. `build/Release`), execute

```bash
cpack3 -G RPM
```

### NixOS

The build dependencies can be loaded using `nix-shell`. Create a file called `default.nix` and populate it with the following:

```
with import <nixpkgs> {};
libcxxStdenv.mkDerivation rec {
    name = "env";
    env = buildEnv { name = name; paths = buildInputs; };
    buildInputs = [
    git
    cmake
    gdb
    openssl
    gnumake
    python
    ];
}
```

When performing the build, pass these additional flags to `cmake`:

```
-DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang
```

### Building the tool

The build process begins in the same directory in which this README resides:

```bash
cd citl-static-analysis
ls README.md
```

We then populate this repository's `git` submodules:

```bash
git submodule init
git submodule update
```

Now we decide between performing a `Release` or a `Debug` build. In what follows
we will perform a `Release` build. To that end, we create a build directory and
change into it:

```bash
mkdir -p build/Release ; cd build/Release
cmake -DCMAKE_BUILD_TYPE=Release ../..
make -j<CPUTHREADS> citl-static-analysis unit-tests
```

If this succeeds, the tool has been built and should be located at `./citl-static-analysis`.

At this point we can run the test suite against the build to ensure basic
functionality:

```bash
ctest
```

The test suite verifies the functionality of the tool by performing end-to-end
tests against a fixed corpus of binaries and checking the resulting output
against known-good values. Thus, if the tests pass, the tool should be ready
for use.

## Building and using a docker container of static-analysis

```bash
docker build -t citl-static-analysis .
docker run --rm -it static-a /bin/sh
citl-static-analysis -logtostderr -nolog_prefix -binfile <target_binary_path>
```


## Running

From within the build directory:

```bash
./citl-static-analysis -logtostderr -nolog_prefix -binfile /path/to/binary
```

A full help output is available by running with (-help) arg.

### Running multiple binaries

There is a small helper utility to run a large collection of binaries with the release build.  First ensure that build/Release/ has been built.
The tool will iterate through all files and directories searching for any file mime type that we support, please run:

```bash
pip install --user python-magic
python ./utils/citl-run-directory.py -d /path/to/bins -o /tmp/data
```

### Helpful options

```
-printcfg       : Pretty prints a complete CFG basic block list.
-all_analyzers  : Toggles analyzers which create large amounts of output (ret distances for example)
-printsyms      : Pretty prints all resolved symbols as well as metadata about them.
--vmodule=CFG=1 : Toggles debugging information about CFG creation.
-addition_funcs : Toggles the Selectable function analyzer to check for call counts of user supplied function names.
                  ex: -addition_funcs "getopt,calloc"
```

### Tests

In order to run all the integration style tests, change directories into the current build directory and run ctest.

Example:

```
cd build/Debug/
ctest
```
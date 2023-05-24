#/bin/sh

# Usage: ./format.sh
# Make sure to have clang-format, gofmt and buildifier installed.
# For debian/ubuntu distros you can install clang-format with `sudo apt install clang-format`
# Go format is installed with golang: `sudo apt install golang`
# For buildifier follow these instructions: 
#  https://github.com/bazelbuild/buildtools/blob/master/buildifier/README.md#setup
# Also for buildifier make sure to setup the correct GOPATH variable.
find . -iname *.h -o -iname *.cc -o -iname *.proto | xargs clang-format -i
gofmt -w -s .
$GOPATH/bin/buildifier -r .

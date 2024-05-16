#/bin/sh

# Usage: ./format.sh
# Make sure to have clang-format, gofmt and buildifier installed.
# For debian/ubuntu distros you can install clang-format with `sudo apt install clang-format`
# Go format is installed with golang: `sudo apt install golang`
# For buildifier follow these instructions:
#  https://github.com/bazelbuild/buildtools/blob/master/buildifier/README.md#setup
# Also for buildifier make sure to setup the correct GOPATH variable.
CLANG_FORMAT="$(which clang-format)"

if [[ ! -z "${OVERRIDE_CLANG_FORMAT}" ]]; then
  CLANG_FORMAT="${OVERRIDE_CLANG_FORMAT}"
fi

find . -iname *.h -o -iname *.cc -o -iname *.proto | xargs "${CLANG_FORMAT}" -i
gofmt -w -s .
$GOPATH/bin/buildifier -r .

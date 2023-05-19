#/bin/sh
find . -iname *.h -o -iname *.cc -o -iname *.proto | xargs clang-format -i

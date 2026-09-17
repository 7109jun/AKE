#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BUILD="${TMPDIR:-/tmp}/ake-native-final-$$"
mkdir -p "$BUILD"
trap 'rm -rf "$BUILD"' EXIT

CFLAGS=(-std=c11 -Wall -Wextra -Werror -I "$ROOT/native")
CXXFLAGS=(-std=c++17 -Wall -Wextra -Werror -I "$ROOT/native")

for f in ake_core ake_pack ake_extract; do
  gcc "${CFLAGS[@]}" -c "$ROOT/native/$f.c" -o "$BUILD/$f.o"
done
for f in ake_windows ake_isolation ake_crypto ake_volume ake_service ake_ipc; do
  g++ "${CXXFLAGS[@]}" -c "$ROOT/native/$f.cpp" -o "$BUILD/$f.o"
done

objs=("$BUILD"/*.o)
for t in test_core test_extract test_dependencies test_network_policy test_environment test_runtime test_runtime_api; do
  gcc "${CFLAGS[@]}" "$ROOT/native/$t.c" "${objs[@]}" -lstdc++ -llzma -o "$BUILD/$t"
  "$BUILD/$t"
done
for t in test_identity test_ipc test_volume test_service; do
  g++ "${CXXFLAGS[@]}" "$ROOT/native/$t.cpp" "${objs[@]}" -llzma -o "$BUILD/$t"
  "$BUILD/$t"
done

echo "AKE native regression suite: PASS"

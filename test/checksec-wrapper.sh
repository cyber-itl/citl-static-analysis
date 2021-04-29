#!/usr/bin/env bash
CHECKSEC="$1 --output csv --file"
CSV_OUTPUT="$($CHECKSEC $2 | head -n 1)"

RELRO="$(echo $CSV_OUTPUT | cut -d, -f 1)"
STACK_GUARD="$(echo $CSV_OUTPUT | cut -d, -f 2)"
NX="$(echo $CSV_OUTPUT | cut -d, -f 3)"
PIE="$(echo $CSV_OUTPUT | cut -d, -f 4)"
RPATH="$(echo $CSV_OUTPUT | cut -d, -f 5)"
RUNPATH="$(echo $CSV_OUTPUT | cut -d, -f 6)"
SYMBOLS="$(echo $CSV_OUTPUT | cut -d, -f 7)"
FORT="$(echo $CSV_OUTPUT | cut -d, -f 8)"

if [ "$RELRO" != "Full RELRO" ]; then
  echo "Binary missing Full RELRO"
  echo "Value: $RELRO"
  exit 1
fi

if [ "$STACK_GUARD" != "Canary found" ]; then
  echo "Binary missing stack guards"
  exit 1
fi

if [ "$NX" != "NX enabled" ]; then
  echo "Binary missing NX"
  exit 1
fi

if [ "$PIE" != "PIE enabled" ]; then
  echo "Binary missing PIE"
  exit 1
fi

if [ "$RPATH" != "No RPATH" ]; then
  echo "Binary has RPATH"
  exit 1
fi

if [ "$RUNPATH" != "No RUNPATH" ]; then
  echo "Binary has RUNPATH"
  exit 1
fi

# REASON TO NOT CHECK: We don't strip binary symbols,
# if [ "$SYMBOLS" != "No SYMTABLES" ]; then
#   echo "Binary has symbols"
#   exit 1
# fi

if [ "$FORT" != "Yes" ]; then
  echo "Binary missing FORTIFY"
  exit 1
fi
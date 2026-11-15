#!/usr/bin/env bash
set -euo pipefail

git -c versionsort.suffix=- tag --sort=-version:refname |
  awk -F. '!seen[$1 "." $2]++' |
  sed -n '1,10p' |
  awk '
    BEGIN {
      printf "[\n  { \"version\": \"dev\", \"path\": \"/heimdall/dev\" }"
    }
    {
      printf ",\n  { \"version\": \"%s\", \"path\": \"/heimdall/%s\" }", $0, $0
    }
    END {
      print "\n]"
    }
  '

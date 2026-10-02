#!/bin/sh
set -eu

top='.github .gitignore .golangci.yml CHANGELOG.md CONTRIBUTING.md LICENSE Makefile README.fr.md README.md SECURITY.md cmd cookbook docs embed.go examples go.mod internal packaging profile testdata tools'
github='dependabot.yml workflows workflows/ci.yml workflows/release.yml workflows/withdraw.yml'

unexpected="$(awk -v top="$top" -v github="$github" '
  BEGIN {
    n = split(top, t, " "); for (i = 1; i <= n; i++) ok[t[i]] = 1
    n = split(github, g, " "); for (i = 1; i <= n; i++) okg[".github/" g[i]] = 1
  }
  {
    sub(/\/$/, "")
    if ($0 == "" || $0 == ".github") next
    split($0, p, "/")
    if (!(p[1] in ok) || (p[1] == ".github" && !($0 in okg))) print
  }')"

if [ -n "$unexpected" ]; then
  echo "not part of the published tree:" >&2
  printf '%s\n' "$unexpected" | sed 's/^/  /' >&2
  exit 1
fi

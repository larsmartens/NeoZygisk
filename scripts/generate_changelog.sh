#!/bin/sh
set -eu

version_name="${1:-$(sed -n 's/.*val verName by extra("\([^"]*\)").*/\1/p' build.gradle.kts | head -n 1)}"
output="${2:-module/changelog.md}"
current_ref="${3:-HEAD}"
base_tag="${4:-$(git tag --sort=-creatordate | grep -Ev '^(daily|latest)$' | head -n 1 || true)}"

if [ -n "$base_tag" ]; then
  range="${base_tag}..${current_ref}"
  range_label="${base_tag}..${version_name} daily"
else
  range="${current_ref}"
  range_label="initial..${version_name} daily"
fi

{
  printf '# %s daily

' "$version_name"
  printf '_Commit titles and messages for `%s`._

' "$range_label"
  git log --reverse --no-merges --date=short     --format='## %s%n%n%b%n- Commit: `%h`%n- Author: %an%n- Date: %ad%n'     $range
} > "$output"

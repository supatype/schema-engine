#!/usr/bin/env bash
# The two release-specific Parameters of the Business Source License in LICENSE: the version named
# in "Licensed Work" and the "Change Date".
#
# Each version has its own Change Date, and the licence names it as a date (covenant 3), so both
# are written when a version is released:
#
#   set   <version> <release-date> [file]  writes the version, and a Change Date four years after
#                                          the release date. release-please.yml runs it on the
#                                          release PR, with the day the PR was last updated.
#   check <version> <release-date> [file]  fails unless the licence names this version and a
#                                          concrete Change Date after the release date and no more
#                                          than four years after it. release.yml runs it on the tag,
#                                          with the date of the tagged commit.
#   selftest [file]                        proves on a copy that check refuses the unreleased
#                                          placeholder and a late date, and passes what set wrote.
#                                          CI runs it.
#
# Dates are YYYY-MM-DD. The file defaults to LICENSE in the current directory. Needs GNU date.

set -euo pipefail

readonly WORK="Licensed Work"
readonly DATE="Change Date"
# The Parameters block aligns every value at column 23.
readonly COLUMN=22

die() {
  echo "licence-parameters: $*" >&2
  exit 1
}

usage() {
  die "usage: $0 set|check <version> <release-date YYYY-MM-DD> [file], or $0 selftest [file]"
}

# Fails unless the argument is a real calendar date in YYYY-MM-DD form.
require_date() {
  [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "'$1' is not a YYYY-MM-DD date"
  [ "$(date -u -d "$1" +%F 2>/dev/null)" = "$1" ] || die "'$1' is not a calendar date"
}

plus_four_years() {
  date -u -d "$1 + 4 years" +%F
}

# "Name:" padded to the value column.
label() {
  printf '%-*s' "$COLUMN" "$1:"
}

# The value of the one line starting with "Name:"; a missing or repeated line is a failure, so an
# edit cannot silently miss.
parameter() {
  local file="$1" name="$2" lines
  lines="$(grep "^${name}:" "$file" || true)"
  [ -n "$lines" ] && [ "$(wc -l <<<"$lines")" -eq 1 ] \
    || die "$file must have exactly one '${name}:' line"
  sed -E "s/^${name}:[[:space:]]*//" <<<"$lines"
}

set_parameters() {
  local version="$1" release_date="$2" file="$3" change_date
  change_date="$(plus_four_years "$release_date")"
  parameter "$file" "$WORK" >/dev/null
  parameter "$file" "$DATE" >/dev/null
  sed -i -E \
    -e "s/^${WORK}:.*$/$(label "$WORK")Supatype Schema Engine ${version}/" \
    -e "s/^${DATE}:.*$/$(label "$DATE")${change_date}/" \
    "$file"
  echo "$file: Supatype Schema Engine ${version}, Change Date ${change_date}"
}

check_parameters() {
  local version="$1" release_date="$2" file="$3" work change_date latest
  work="$(parameter "$file" "$WORK")"
  [ "$work" = "Supatype Schema Engine ${version}" ] \
    || die "$file names '$work', not Supatype Schema Engine ${version}"
  change_date="$(parameter "$file" "$DATE")"
  require_date "$change_date"
  latest="$(plus_four_years "$release_date")"
  [[ "$change_date" > "$release_date" ]] \
    || die "$file's Change Date ${change_date} is not after the release date ${release_date}"
  [[ ! "$change_date" > "$latest" ]] \
    || die "$file's Change Date ${change_date} is more than four years after ${release_date}"
  echo "$file: Supatype Schema Engine ${version}, Change Date ${change_date}"
}

# Both directions on a copy: what the release workflows rely on, proven before a release needs it.
selftest() {
  copy="$(mktemp)"
  # Global, so the EXIT trap still sees it when a failed step exits from inside a function.
  trap 'rm -f "$copy"' EXIT
  cp "$1" "$copy"
  if (check_parameters 9.9.9 2026-10-20 "$copy") 2>/dev/null; then
    die "selftest: check passed a licence with no Change Date"
  fi
  set_parameters 9.9.9 2026-10-20 "$copy" >/dev/null
  check_parameters 9.9.9 2026-10-21 "$copy" >/dev/null
  if (check_parameters 9.9.9 2026-10-19 "$copy") 2>/dev/null; then
    die "selftest: check passed a Change Date more than four years out"
  fi
  echo "licence-parameters: selftest passed"
}

main() {
  if [ "${1:-}" = selftest ]; then
    [ $# -le 2 ] || usage
    selftest "${2:-LICENSE}"
    return
  fi
  [ $# -ge 3 ] && [ $# -le 4 ] || usage
  local mode="$1" version="$2" release_date="$3" file="${4:-LICENSE}"
  require_date "$release_date"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] \
    || die "'$version' is not a version"
  [ -f "$file" ] || die "$file does not exist"
  case "$mode" in
    set) set_parameters "$version" "$release_date" "$file" ;;
    check) check_parameters "$version" "$release_date" "$file" ;;
    *) usage ;;
  esac
}

main "$@"

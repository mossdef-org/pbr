#!/bin/sh
#
# check-ucode-syntax.sh — compile every .uc file with a given ucode binary.
#
# Catches syntax that is too NEW for the oldest ucode pbr must support. Newer
# ucode accepts everything older accepts, so building against master proves
# nothing about the routers people actually run — point this at the OLDEST
# supported interpreter.
#
# Usage: tests/check-ucode-syntax.sh [path-to-ucode]     (default: ucode in PATH)
#
# Files are classified by whether they contain a top-level `export`:
#   module -> must be reached through an `import` wrapper; compiling one
#             directly stops at the first export with "Exports may only appear
#             at top level of a module", which is NOT a real failure.
#   script -> compiled directly; these use top-level `return` and are rejected
#             by the import wrapper on every version.
# Getting this backwards produces confident nonsense in both directions.
#
set -u

UCODE="${1:-ucode}"
command -v "$UCODE" >/dev/null 2>&1 || { echo "no ucode at '$UCODE'" >&2; exit 2; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "ucode: $UCODE"
"$UCODE" -e 'print("")' 2>/dev/null || { echo "ucode not runnable" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Canary: prove this check is capable of failing. A scan that cannot fail is
# not evidence — an earlier version of this reported "all files compile" while
# actually iterating over an empty directory.
# ---------------------------------------------------------------------------
printf 'let o = { shorthand() { return 1; } };\nexport default o;\n' > "$TMP/canary.uc"
echo "import * as m from \"$TMP/canary.uc\";" > "$TMP/w.uc"
if "$UCODE" -c -o /dev/null "$TMP/w.uc" >/dev/null 2>&1; then
	echo "CANARY PASSED — this ucode accepts shorthand methods, so it is NOT an"
	echo "old-enough interpreter to be a useful compatibility gate." >&2
	exit 2
fi
echo "canary: correctly rejected (check is live)"

n=0; bad=0

# Read the file list from a temp file rather than a pipeline: a `find | while`
# pipeline runs the loop in a subshell under POSIX sh, and the counters below
# would be lost when it exits. Redirecting from a file keeps the loop in this
# shell. (Filenames containing newlines would still break this; none do, and
# `find -print0` needs `read -d` which is not POSIX.)
find "$ROOT" -name '*.uc' | sort > "$TMP/files.txt"

while IFS= read -r f; do
	[ -n "$f" ] || continue
	n=$((n + 1))
	rel="${f#$ROOT/}"

	if grep -qE '^[[:space:]]*export' "$f"; then
		echo "import * as m from \"$f\";" > "$TMP/w.uc"
		target="$TMP/w.uc"; kind="module"
	else
		target="$f"; kind="script"
	fi

	if err="$("$UCODE" -c -o /dev/null "$target" 2>&1)"; then
		printf '  ok   %-8s %s\n' "$kind" "$rel"
	else
		bad=$((bad + 1))
		printf '  FAIL %-8s %s\n' "$kind" "$rel"
		echo "$err" | sed 's/^/         /' | head -4
	fi
done < "$TMP/files.txt"

echo
echo "checked $n file(s), $bad failed"
[ "$bad" -eq 0 ] || exit 1

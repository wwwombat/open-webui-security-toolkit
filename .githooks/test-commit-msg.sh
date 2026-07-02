#!/bin/sh
# Test harness for the commit-msg hook (.githooks/commit-msg).
#
# Runs the hook against a set of crafted commit messages and checks the
# result against an expected output. Exits non-zero if any case fails.
#
# Usage:  .githooks/test-commit-msg.sh
# Runs standalone -- does not touch git state or create commits.

hook="$(dirname "$0")/commit-msg"
tmp="$(mktemp)"
pass=0
fail=0

# check NAME  INPUT  EXPECTED
# Feeds INPUT through the hook and compares stdout-equivalent output to EXPECTED.
# %b is interpreted by printf, so use \n for newlines in both arguments.
check() {
	name=$1
	printf '%b' "$2" > "$tmp"
	"$hook" "$tmp"
	got=$(cat "$tmp")
	want=$(printf '%b' "$3")
	if [ "$got" = "$want" ]; then
		pass=$((pass + 1))
		printf 'ok   - %s\n' "$name"
	else
		fail=$((fail + 1))
		printf 'FAIL - %s\n' "$name"
		printf '  --- expected ---\n'; printf '%s\n' "$want" | sed 's/^/  | /'
		printf '  --- got --------\n'; printf '%s\n' "$got"  | sed 's/^/  | /'
	fi
}

check "strips a trailing Claude trailer" \
	"Subject\n\nBody paragraph.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n" \
	"Subject\n\nBody paragraph."

check "keeps a human co-author, drops Claude" \
	"Subject\n\nCo-authored-by: Jane Dev <jane@example.com>\nCo-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>\n" \
	"Subject\n\nCo-authored-by: Jane Dev <jane@example.com>"

check "leaves a message with no trailer untouched" \
	"Normal commit\n\nJust a body.\n" \
	"Normal commit\n\nJust a body."

check "keeps a Claude mention in body prose" \
	"Add hook\n\nRemoves Co-Authored-By: Claude trailers from messages.\n" \
	"Add hook\n\nRemoves Co-Authored-By: Claude trailers from messages."

check "keeps a trailer-shaped line in the body, not the final block" \
	"Document format\n\nExample:\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n\nSee README.\n" \
	"Document format\n\nExample:\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n\nSee README."

check "keeps body copy but strips the real trailing trailer" \
	"Document format\n\nExample:\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n\nSee README.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n" \
	"Document format\n\nExample:\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\n\nSee README."

check "handles case-insensitive trailer key" \
	"Subject\n\nco-authored-by: Claude Opus 4.8 <noreply@anthropic.com>\n" \
	"Subject"

check "strips trailer despite trailing blank lines after it" \
	"Subject\n\nCo-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>\n\n\n" \
	"Subject"

rm -f "$tmp"
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

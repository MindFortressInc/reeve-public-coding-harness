#!/bin/bash
# Tests for stash-guard.py -- run: bash hooks/stash-guard.test.sh
# Builds throwaway repos (a main checkout with one linked worktree, a solo repo
# with none, and a plain directory) and feeds the hook real PreToolUse payloads.
# Nothing here ever runs `git stash`; the hook is only asked to judge it.
# `VAR=val check ...` below scopes VAR to one call only in bash's default mode;
# sh / POSIX mode keeps it set afterwards, leaking a fake PATH into later checks.
[ -n "${BASH_VERSION:-}" ] || { echo "run with bash: bash $0" >&2; exit 2; }
set +o posix
HOOK="$(CDPATH= cd "$(dirname "$0")" && pwd)/stash-guard.py"  # CDPATH= : cd prints nothing
pass=0; fail=0
T=$(cd "$(mktemp -d)" && pwd -P); trap 'rm -rf "$T"' EXIT
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE
# No developer git config reaches the fixtures or the hook's probes (a global
# commit.gpgSign or alias would change results); scoped HOME= / XDG_CONFIG_HOME=
# checks below still pick their own config dirs.
export HOME="$T/home" GIT_CONFIG_NOSYSTEM=1; mkdir -p "$HOME"
unset XDG_CONFIG_HOME GIT_CONFIG GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS

g() { git -c user.email=t@t -c user.name=t -c init.defaultBranch=main "$@" >/dev/null 2>&1; }
MAIN="$T/main"; WT="$T/main.wt"; SOLO="$T/solo"; PLAIN="$T/plain"
mkdir -p "$MAIN" "$SOLO" "$PLAIN"
for r in "$MAIN" "$SOLO"; do
  g -C "$r" init && echo x > "$r/f" && g -C "$r" add f && g -C "$r" commit -m init \
    || { echo "setup failed: cannot create repo at $r"; exit 1; }
done
g -C "$MAIN" worktree add "$WT" -b wt-branch
[ -f "$WT/.git" ] || { echo "setup failed: no linked worktree at $WT"; exit 1; }

# $1 tool_name, $2 command, $3 cwd -> a Claude Code PreToolUse payload
j() { python3 -c 'import json,sys; print(json.dumps({"session_id":"s1","transcript_path":"/x.jsonl","cwd":sys.argv[3],"hook_event_name":"PreToolUse","tool_name":sys.argv[1],"tool_input":{"command":sys.argv[2],"description":"d"}}))' "$@"; }

# $1 name, $2 command, $3 cwd, $4 expect ALLOW|DENY, $5 optional substring the deny reason must contain
# A VAR=val prefix on a check call reaches the hook process's environment
check() {
  out=$(j Bash "$2" "$3" | python3 "$HOOK" 2>"$T/stderr"); rc=$?
  if [ $rc -ne 0 ]; then fail=$((fail+1)); echo "FAIL: $1 (exit $rc)"; sed 's/^/  /' "$T/stderr"; rm -f "$T/stderr"; return; fi
  rm -f "$T/stderr"
  case "$4" in
    ALLOW) [ -z "$out" ] && { pass=$((pass+1)); echo "ok   ALLOW  $1"; return; } ;;
    DENY) echo "$out" | python3 -c '
import json,sys
d=json.load(sys.stdin)["hookSpecificOutput"]
if d.get("hookEventName")!="PreToolUse" or d.get("permissionDecision")!="deny": sys.exit(1)
if sys.argv[1] not in d.get("permissionDecisionReason",""): sys.exit(1)
' "${5:-}" 2>/dev/null && { pass=$((pass+1)); echo "ok   DENY   $1"; return; } ;;
  esac
  fail=$((fail+1)); echo "FAIL: $1 (expected $4)"; echo "  got: ${out:-<empty>}"
}

# --- mutating stash inside a linked worktree: denied
check "bare git stash in linked wt"         "git stash"                       "$WT" DENY "linked worktree"
check "git stash pop in linked wt"          "git stash pop"                   "$WT" DENY "git worktree add"
check "git -C <wt> stash push -- f"         "git -C $WT stash push -- f"      "$PLAIN" DENY "linked worktree"
check "stash apply"                         "git stash apply stash@{1}"       "$WT" DENY
check "stash drop"                          "git stash drop"                  "$WT" DENY
check "stash save"                          "git stash save 'wip'"            "$WT" DENY
check "stash clear"                         "git stash clear"                 "$WT" DENY
check "stash -u (implicit push)"            "git stash -u"                    "$WT" DENY
check "stash -- path (implicit push)"       "git stash -- f"                  "$WT" DENY
check "stash branch"                        "git stash branch x"              "$WT" DENY
check "reason names safe alternatives"      "git stash"                       "$WT" DENY "git show <sha>:<path>"

# --- chains, wrappers, prefixes
check "after && in chain"                   "git status && git stash"         "$WT" DENY
check "after ; in chain"                    "git status; git stash pop"       "$WT" DENY
check "after || in chain"                   "false || git stash"              "$WT" DENY
check "after pipe"                          "true | git stash"                "$WT" DENY
check "on a later line"                     $'ls\ngit stash pop'              "$WT" DENY
check "list first does not launder pop"     "git stash list && git stash pop" "$WT" DENY
check "cd into wt, then stash"              "cd $WT && git stash"             "$PLAIN" DENY
check "cd relative, then stash"             "cd main.wt; git stash pop"       "$T" DENY
check "subshell cd + stash"                 "(cd $WT && git stash)"           "$PLAIN" DENY
check "env assignment prefix"               "FOO=1 git stash"                 "$WT" DENY
check "env(1) prefix with option"           "env -u X FOO=1 git stash pop"    "$WT" DENY
check "-c option before stash"              "GIT_PAGER=cat git -c core.x=y --no-pager stash" "$WT" DENY
check "absolute git binary"                 "/usr/bin/git stash pop"          "$WT" DENY
check "relative -C from parent"             "git -C main.wt stash"            "$T" DENY
check "-C via shell variable"               "W=$WT; git -C \"\$W\" stash pop" "$PLAIN" DENY
check "-C via exported variable"            "export W=$WT && git -C \${W} stash" "$PLAIN" DENY
check "bash -c wrapper"                     "bash -c 'git stash pop'"         "$WT" DENY
check "bash -lc combined flags"             "bash -lc 'git stash pop'"        "$WT" DENY
check "sh -ec combined flags"               "sh -ec 'git stash'"              "$WT" DENY
check "bash -o opt then -c"                 "bash -o pipefail -c 'git stash'" "$WT" DENY
check "command substitution"                "x=\$(git stash create); echo \$x" "$WT" DENY
check "absolute shell path -c"              "/bin/bash -c 'git stash pop'"    "$WT" DENY
check "absolute env(1) path"                "/usr/bin/env git stash"          "$WT" DENY
check "unquoted \$(...) as -C fails closed" "git -C \$(git rev-parse --show-toplevel) stash pop" "$PLAIN" DENY "could not resolve"
check "unquoted \$(...) as cd fails closed" "cd \$(git rev-parse --show-toplevel) && git stash" "$PLAIN" DENY "could not resolve"
check "untracked \$1 as -C fails closed"    "git -C \$1 stash"                "$PLAIN" DENY "could not resolve"
check "stash inside unquoted \$(...) arg"   "echo \$(git stash pop) done"     "$WT" DENY
check "\$(...) arg does not hide later cmd" "echo \$(date) && git stash"      "$WT" DENY
check "\$(...) with a ) in quotes"          "echo \$(echo ')') && git stash list" "$WT" ALLOW
check "backslash-newline continuation"      $'git \\\n  stash pop'            "$WT" DENY
check "cd - is untracked, fails closed"     "cd $SOLO && cd - && git stash"  "$WT" DENY "could not resolve"
check "unresolvable -C fails closed"       "git -C \"\$NOPE_UNSET_VAR\" stash" "$PLAIN" DENY "could not resolve"

check "nesting past the recursion bound"     "eval eval eval eval git stash pop" "$WT" DENY "nested too deeply"
check "scoped VAR= does not retarget -C \$VAR" "W=$WT; W=$SOLO git -C \"\$W\" stash pop" "$PLAIN" DENY "linked worktree"
check "subshell cd does not leak out"       "(cd $SOLO); git stash pop"       "$WT" DENY "linked worktree"
check "\$(...) cd does not leak out"        "echo \$(cd $SOLO) && git stash pop" "$WT" DENY "linked worktree"
check "subshell cd into wt stays inside"    "(cd $WT); git stash pop"         "$SOLO" ALLOW
check "env -C retargets git"                "env -C $WT git stash pop"        "$SOLO" DENY "linked worktree"
check "env --chdir= retargets git"          "env --chdir=$WT git stash"       "$SOLO" DENY "linked worktree"
check "failed cd leaves cwd unknown"        "cd $T/nope || true; git stash pop" "$WT" DENY "could not resolve"
check "\$(...) inside double quotes"        "echo \"\$(git stash pop)\""     "$WT" DENY
check "escaped \\\$( in double quotes is text" "echo \"\\\$(git stash pop)\"" "$WT" ALLOW
GIT_DIR="$MAIN/.git/worktrees/main.wt" GIT_WORK_TREE="$WT" \
check "inherited GIT_DIR names a linked wt" "git stash pop"                   "$PLAIN" DENY "linked worktree"
check "comment ) inside \$(...) does not close it" $'echo "$( # )\ngit stash pop\n)"' "$WT" DENY
check "\$# inside \$(...) is not a comment"   "echo \$(echo \$#) && git stash list" "$WT" ALLOW
check "nested env -C applies in order"       "env -C $MAIN env -C . git stash clear" "$SOLO" DENY "other worktree"
check "nested env -C relative to the last"   "env -C $T env -C main.wt git stash"  "$SOLO" DENY "linked worktree"
GIT_DIR="$SOLO/.git" \
check "env -u drops an inherited GIT_DIR"    "env -u GIT_DIR git stash clear"      "$WT" DENY "linked worktree"
GIT_DIR="$SOLO/.git" \
check "env --unset=GIT_DIR"                  "env --unset=GIT_DIR git stash"       "$WT" DENY "linked worktree"
GIT_DIR="$SOLO/.git" \
check "env -i drops an inherited GIT_DIR"    "env -i git stash clear"              "$WT" DENY "linked worktree"
GIT_DIR="$SOLO/.git" \
check "env -u GIT_DIR then reassigned"       "env -u GIT_DIR GIT_DIR=$SOLO/.git git stash" "$WT" ALLOW
check "scoped GIT_DIR reaches bash -c"       "GIT_DIR=$MAIN/.git bash -c 'git stash clear'" "$SOLO" DENY "other worktree"
check "unresolvable scoped GIT_DIR, bash -c" "GIT_DIR=\$NOPE_UNSET_VAR bash -c 'git stash'" "$SOLO" DENY "could not resolve"
check "eval cd carries to the next segment"  "eval 'cd $MAIN'; git stash clear"   "$SOLO" DENY "other worktree"
check "eval export carries on"               "eval 'export W=$WT'; git -C \"\$W\" stash" "$PLAIN" DENY "linked worktree"
check "eval in a subshell does not leak"     "(eval 'cd $WT'); git stash pop"     "$SOLO" ALLOW
check "A=b eval scopes A to the eval only"   "GIT_DIR=$SOLO/.git eval true; git stash pop" "$WT" DENY "linked worktree"
check "bash -c cd does not leak out"         "bash -c 'cd $SOLO'; git stash pop"  "$WT" DENY "linked worktree"
check "command -p wrapper option"            "command -p git stash pop"        "$WT" DENY "linked worktree"
check "time -p wrapper option"               "time -p git stash pop"           "$WT" DENY "linked worktree"
check "sudo -u USER wrapper option"          "sudo -u nobody git stash pop"    "$WT" DENY "linked worktree"
check "exec -a NAME wrapper option"          "exec -a x git stash"             "$WT" DENY "linked worktree"
check "sudo -D retargets git"                "sudo -D $WT git stash pop"       "$SOLO" DENY "linked worktree"
check "conditional cd may not have run"      "false && cd $SOLO; git stash pop" "$WT" DENY "could not resolve"
check "cd before || may have failed"         "cd $SOLO || git stash pop"       "$WT" DENY "could not resolve"
check "cd && stash keeps the cd target"      "cd $SOLO && git stash pop"       "$WT" ALLOW
check "2>&1 is not a list separator"         "cd $SOLO 2>&1 && git stash pop"  "$WT" ALLOW
check "backquote cd does not leak out"       "echo \`cd $SOLO\`; git stash pop" "$WT" DENY "linked worktree"
check "stash inside backquotes"              "echo \`git stash pop\`"          "$WT" DENY
check "stash in backquotes in double quotes" "echo \"\`git stash pop\`\""      "$WT" DENY
check "heredoc fed to bash is scanned"       $'bash <<\'EOF\'\ngit stash pop\nEOF' "$WT" DENY "linked worktree"
check "heredoc fed to sh -s is scanned"      $'sh -s <<EOF\ncd /\ngit -C '"$WT"$' stash\nEOF' "$PLAIN" DENY "linked worktree"
check "heredoc to bash -c stays data"        $'bash -c cat <<\'EOF\'\ngit stash pop\nEOF' "$WT" ALLOW
check "heredoc delimiter with a dash"        $'cat <<EOF-1\nx\nEOF-1\ngit stash pop' "$WT" DENY "linked worktree"
check "heredoc delimiter partly quoted"      $'cat <<"EO"F\nx\nEOF\ngit stash pop' "$WT" DENY "linked worktree"
check "eval of a tracked variable"           "CMD='git stash pop'; eval \"\$CMD\"" "$WT" DENY "linked worktree"
check "bash -c of a tracked variable"        "S='git stash pop'; bash -c \"\$S\"" "$WT" DENY "linked worktree"
check "quote-joined stash word"              "git sta\"\"sh pop"               "$WT" DENY "linked worktree"
check "partly quoted stash word"             "git sta\"sh\" pop"               "$WT" DENY "linked worktree"
check "quote-joined stash in bash -c body"   "bash -c 'git sta\"\"sh pop'"     "$WT" DENY "linked worktree"
check "piped cd runs in a subshell"          "cd $SOLO | cat; git stash clear" "$MAIN" DENY "other worktree"
check "backgrounded cd runs in a subshell"   "cd $SOLO & git stash clear"      "$MAIN" DENY "other worktree"
check "last pipeline cd is uncertain"        "true | cd $SOLO; git stash clear" "$MAIN" DENY "could not resolve"
check "cd before a pipeline keeps its target" "cd $SOLO && true | git stash pop" "$WT" ALLOW
check "\$(...) in an unquoted data heredoc"  $'cat <<EOF\n$(git stash clear)\nEOF' "$WT" DENY "linked worktree"
check "\$(...) in a quoted data heredoc"     $'cat <<\'EOF\'\n$(git stash clear)\nEOF' "$WT" ALLOW
check "shell heredoc uses its env -C"        $'env -C '"$MAIN"$' bash <<\'EOF\'\ngit stash clear\nEOF' "$SOLO" DENY "other worktree"
check "shell heredoc runs before a later cd" $'bash <<\'EOF\'; cd '"$SOLO"$'\ngit stash pop\nEOF' "$WT" DENY "linked worktree"
check "conditional export may not have run"  "false && export GIT_DIR=$SOLO/.git; git stash clear" "$MAIN" DENY "may not have run"
check "export in the same && list applies"   "true && export GIT_DIR=$SOLO/.git && git stash clear" "$MAIN" ALLOW
check "bash -c body assignment governs its cd" "DEST=$SOLO; bash -c 'DEST=$MAIN; cd \"\$DEST\"; git stash clear'" "$SOLO" DENY "other worktree"
check "eval body assignment governs its cd"  "DEST=$SOLO; eval 'DEST=$MAIN; cd \"\$DEST\"'; git stash clear" "$SOLO" DENY "could not resolve"
# --- redirections, $PWD, exports, unset, symlinks, here strings, branches,
#     expanded command words, wrappers and aliases
check "leading redirection before git"      "2>/dev/null git stash clear"     "$WT" DENY "linked worktree"
check "redirection between git and stash"   "git 2>/dev/null stash clear"     "$WT" DENY "linked worktree"
check "spaced leading redirection"          "> /dev/null git stash pop"       "$WT" DENY "linked worktree"
check "trailing redirection keeps list"     "git stash list 2>/dev/null"      "$WT" ALLOW
check "quoted > is not a redirection"       "bash -c '>/dev/null git stash pop'" "$WT" DENY "linked worktree"
check "cd updates \$PWD"                    "cd $MAIN && git -C \"\$PWD\" stash clear" "$SOLO" DENY "other worktree"
check "cd updates \$OLDPWD"                 "cd $SOLO && git -C \"\$OLDPWD\" stash clear" "$WT" DENY "linked worktree"
check "unexported assignment skips git"     "GIT_DIR=$SOLO/.git; git stash clear" "$WT" DENY "linked worktree"
check "unexported assignment skips bash -c" "GIT_DIR=$SOLO/.git; bash -c 'git stash clear'" "$WT" DENY "linked worktree"
check "assign then export reaches git"      "GIT_DIR=$SOLO/.git; export GIT_DIR; git stash clear" "$WT" ALLOW
check "export -n un-exports"                "export GIT_DIR=$SOLO/.git; export -n GIT_DIR; git stash clear" "$WT" DENY "linked worktree"
check "scoped assignment still reaches git" "GIT_DIR=$SOLO/.git git stash clear" "$WT" ALLOW
check "unset drops a tracked export"        "export GIT_DIR=$SOLO/.git; unset GIT_DIR; git stash clear" "$WT" DENY "linked worktree"
GIT_DIR="$SOLO/.git" \
check "unset drops an inherited GIT_DIR"    "unset GIT_DIR; git stash clear"  "$WT" DENY "linked worktree"
mkdir -p "$WT/sub"; ln -s "$WT/sub" "$PLAIN/link"
check "git -C follows a symlink before .."  "git -C link/.. stash pop"        "$PLAIN" DENY "linked worktree"
check "env -C follows a symlink before .."  "env -C link/.. git stash clear"  "$PLAIN" DENY "linked worktree"
check "cd stays logical across a symlink"   "cd link/.. && git stash pop"     "$PLAIN" ALLOW
check "cd -P follows the symlink"           "cd -P link/.. && git stash pop"  "$PLAIN" DENY "linked worktree"
g clone --bare "$MAIN" "$T/bare.git"; g -C "$T/bare.git" worktree add "$T/bare.wt" -b bare-wt
check "--work-tree reaches the probe"       "git --git-dir=$T/bare.git --work-tree=$T/bare.wt stash clear" "$PLAIN" DENY "other worktree"
check "relative --git-dir after a later -C" "git --git-dir=.git -C $MAIN stash clear" "$SOLO" DENY "other worktree"
check "here string fed to bash"             "bash <<< 'git stash clear'"      "$WT" DENY "linked worktree"
check "here string to cat stays data"       "cat <<< 'git stash clear'"       "$WT" ALLOW
check "here string is not a heredoc"        $'cat <<< text\ngit stash pop'   "$WT" DENY "linked worktree"
check "cd in a skipped if branch"           "if false; then cd $SOLO; fi; git stash clear" "$WT" DENY "could not resolve"
check "cd in then, stash in else"           "if false; then cd $SOLO; else git stash clear; fi" "$WT" DENY "could not resolve"
check "cd and stash in one branch"          "if true; then cd $SOLO && git stash pop; fi" "$WT" ALLOW
check "cd in a loop body may not run"       "while false; do cd $SOLO; done; git stash pop" "$WT" DENY "could not resolve"
check "command word from a variable"        "B=git; \"\$B\" stash pop"        "$WT" DENY "linked worktree"
check "subcommand from a variable"          "S=stash; git \"\$S\" pop"        "$WT" DENY "linked worktree"
check "read-only stash sub from a variable" "S=list; git stash \"\$S\""       "$WT" ALLOW
check "unknown subcommand word, shared"     "git \"\$NOPE_UNSET_VAR\" pop"    "$WT" DENY "could not be resolved"
check "unknown subcommand word, solo"       "git \"\$NOPE_UNSET_VAR\" pop"    "$SOLO" ALLOW
check "unknown command word, shared"        "\"\$NOPE_UNSET_VAR\" stash pop"  "$WT" DENY "could not be resolved"
check "unknown command word, unrelated"     "\"\$NOPE_UNSET_VAR\" notes.md"   "$WT" ALLOW
check "timeout wrapper"                     "timeout 10 git stash pop"        "$WT" DENY "linked worktree"
check "timeout with options"                "timeout -k 5 --signal=TERM 10 git stash clear" "$WT" DENY "linked worktree"
check "timeout of a read-only stash"        "timeout 10 git stash list"       "$WT" ALLOW
check "nice wrapper"                        "nice -n 5 git stash"             "$WT" DENY "linked worktree"
check "xargs wrapper"                       "echo pop | xargs git stash"      "$WT" DENY "linked worktree"
check "-c shell alias runs a stash"         "git -c alias.shelf='!git stash pop' shelf" "$WT" DENY "linked worktree"
check "-c git alias runs a stash"           "git -c alias.sv='stash pop' sv"  "$WT" DENY "linked worktree"
check "chained aliases reach a stash"       "git -c alias.a=b -c 'alias.b=stash pop' a" "$WT" DENY "linked worktree"
check "shell alias calls a -c alias"        "git -c 'alias.b=stash pop' -c 'alias.a=!git b' a" "$WT" DENY "linked worktree"
check "alias to a read-only stash"          "git -c alias.sl='stash list' sl" "$WT" ALLOW
check "alias to status"                     "git -c alias.st=status st"       "$WT" ALLOW
g -C "$MAIN" config alias.shelf2 'stash pop'
check "configured alias runs a stash"       "git shelf2"                      "$WT" DENY "linked worktree"
check "configured alias, other repo"        "git shelf2"                      "$SOLO" ALLOW
check "--config-env alias runs a stash"     "A='stash clear' git --config-env=alias.s=A s" "$WT" DENY "linked worktree"
check "--config-env alias, exported var"    "export A='stash pop'; git --config-env alias.s=A s" "$WT" DENY "linked worktree"
check "--config-env alias, read-only"       "A='stash list' git --config-env=alias.s=A s" "$WT" ALLOW
check "--config-env alias, unset var"       "git --config-env=alias.s=NOPE_UNSET_VAR s" "$WT" ALLOW
check "--config-env alias, uncertain var"   "true && export A='stash pop'; git --config-env=alias.s=A s" "$WT" DENY "cannot be resolved"
mkdir -p "$MAIN/sub" "$SOLO/sub"
check "shell alias runs from the top level" "git -c 'alias.s=!git -C sub stash clear' s" "$MAIN/sub" DENY "other worktree"
check "shell alias top level, solo repo"    "git -c 'alias.s=!git -C sub stash clear' s" "$SOLO/sub" ALLOW
check "function body cd is not run"         "f() { cd $SOLO; }; git stash clear" "$WT" DENY
check "called function's cd is uncertain"   "f() { cd $WT; }; f; git stash clear" "$SOLO" DENY
check "function keyword form"               "function f { cd $SOLO; }; git stash clear" "$WT" DENY
check "function body on its own line"       $'f()\n{ cd '"$SOLO"$'; }\ngit stash clear' "$WT" DENY
check "stash inside a function body"        "f() { git stash pop; }"          "$WT" DENY "linked worktree"
check "loop's later pass sees its own cd"   "for i in 1 2; do git stash clear; cd $WT; done" "$SOLO" DENY "could not resolve"
check "while loop's later pass, too"         "while true; do git stash pop; cd $MAIN; done" "$SOLO" DENY "could not resolve"
check "loop-carried export reaches pass 2"   "for i in 1 2; do git stash pop; export GIT_DIR=$MAIN/.git; done" "$SOLO" DENY "may not have run"
check "loop-carried value chain settles"     "C=$SOLO; B=$SOLO; for i in 1 2 3; do cd \"\$C\"; git stash pop; C=\$B; B=$WT; done" "$SOLO" DENY "could not resolve"
check "loop that stays in one solo repo"     "for i in 1 2; do cd $SOLO; git stash pop; done" "$WT" ALLOW
check "loop without state changes, solo"     "for i in 1 2; do git stash pop; done" "$SOLO" ALLOW
check "command skips a shadowing function"   "git() { :; }; command git stash pop" "$WT" DENY "linked worktree"
check "exec launcher skips the function"     "git() { :; }; exec git stash pop" "$WT" DENY "linked worktree"
check "env launcher skips the function"      "git() { :; }; env git stash clear" "$WT" DENY "linked worktree"
check "time keeps function lookup"           "git() { :; }; time git stash clear" "$WT" ALLOW
check "env cd runs in a child"               "env cd $SOLO; git stash pop"     "$WT" DENY "linked worktree"
check "nohup export runs in a child"         "nohup export GIT_DIR=$SOLO/.git; git stash pop" "$WT" DENY "linked worktree"
check "env A=b sets no shell state"          "env PWD=$SOLO; git -C \"\$PWD\" stash pop" "$WT" DENY "linked worktree"
check "command cd is the builtin"            "cd() { :; }; command cd $SOLO; git stash pop" "$WT" ALLOW
check "function forwards \"\$@\""            "f() { \"\$@\"; }; f git stash pop" "$WT" DENY "linked worktree"
check "function forwards \$1 into git"       "f() { git \"\$1\" clear; }; f stash" "$WT" DENY "linked worktree"
check "function forwards \$1 as the command" "f() { \$1 clear; }; f 'git stash'" "$WT" DENY "linked worktree"
check "the \$1 body alone runs no stash"     "f() { \$1 clear; }"              "$WT" ALLOW
check "function forwards a read-only stash"  "f() { \"\$@\"; }; f git stash list" "$WT" ALLOW
check "function echoes forwarded args"       "f() { echo \"\$@\"; }; f git stash pop" "$WT" ALLOW
check "function without cd, solo repo"      "f() { echo hi; }; git stash clear" "$SOLO" ALLOW
check "env -S runs its split command"       "env -S 'git stash clear'"        "$WT" DENY "linked worktree"
check "env -S attached operand"             "env -iS'git stash pop'"          "$WT" DENY "linked worktree"
check "env --split-string"                  "env --split-string='git stash'"  "$WT" DENY "linked worktree"
check "env -S read-only stash"              "env -S 'git stash list'"         "$WT" ALLOW
check "pushd -n keeps the cwd"              "pushd -n $SOLO; git stash clear" "$WT" DENY "linked worktree"
check "pushd -n away from a worktree"       "pushd -n $WT; git stash clear"   "$SOLO" ALLOW
check "pushd changes the cwd"               "pushd $WT; git stash clear"      "$SOLO" DENY "linked worktree"
check "bare pushd target is untracked"      "pushd; git stash clear"          "$SOLO" DENY "unknown"
# --- arithmetic $(( )) and unresolvable command words (both used to
#     false-deny ordinary status / pytest commands in a linked worktree)
check "arithmetic \$(( )) is not a command"  "echo \"age=\$(( \$(date +%s) - \$(date +%s) ))s\"" "$WT" ALLOW
check "unquoted arithmetic assignment"      "x=\$(( 1 + 2 )); echo \$x"        "$WT" ALLOW
check "stash in arithmetic's \$(...)"       "echo \$(( \$(git stash clear) + 0 ))" "$WT" DENY "linked worktree"
check "read-only stash in arithmetic"       "echo \$(( \$(git stash list | wc -l) + 0 ))" "$WT" ALLOW
check "arithmetic text spelling a stash"    "echo \$((git stash pop))"         "$WT" DENY "linked worktree"
check "arithmetic in an unquoted heredoc"   $'cat <<EOF\n$(( $(git stash clear) + 1 ))\nEOF' "$WT" DENY "linked worktree"
check "\$( ( ) ) stays a substitution"       "echo \$( (git stash pop) )"       "$WT" DENY "linked worktree"
check "unresolved command word, unknown cwd" "cd $T/nope; \$NOPE_UNSET_VAR -m pytest -q" "$WT" ALLOW
check "unresolved command word stashing, unknown cwd" "cd $T/nope; \"\$NOPE_UNSET_VAR\" stash pop" "$WT" DENY "could not be resolved"
check "unresolved command word, configured alias" "\"\$NOPE_UNSET_VAR\" shelf2" "$WT" DENY "could not be resolved"
check "arithmetic with a stash-list substitution" "echo \"age=\$(( \$(date +%s) - \$(git stash list | wc -l) ))s\"" "$WT" ALLOW
check "\$(( whose # hides a ) is a substitution" $'echo $((echo hi #)\ns=sta; git ${s}sh pop))' "$WT" DENY "linked worktree"
check "\$(( whose quoted ) is a substitution"  "echo \$((echo \")\"; s=sta; git \${s}sh pop))" "$WT" DENY "linked worktree"
check "unresolved command word, inline alias, unknown cwd" "cd $T/nope; \"\$NOPE_UNSET_VAR\" -c alias.p='stash pop' p" "$WT" DENY "could not be resolved"
check "unresolved command word, unresolvable -c" "\"\$NOPE_UNSET_VAR\" -c \"alias.p=\$NOPE_UNSET_VAR\" p" "$WT" DENY "could not be resolved"
check "unresolved command word, uncertain HOME" "true && export HOME=$T/althome; \"\$NOPE_UNSET_VAR\" wipe" "$WT" DENY "could not be resolved"
check "\$(( with escaped parens is a substitution" "echo \$((: \\(\\); git sta\${x}sh pop))" "$WT" DENY "linked worktree"
check "unresolved command word, env-config alias" "cd $T/nope; GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.p GIT_CONFIG_VALUE_0=stash \"\$NOPE_UNSET_VAR\" p" "$WT" DENY "could not be resolved"
check "GIT_CONFIG_NOSYSTEM defines no alias" "cd $T/nope; GIT_CONFIG_NOSYSTEM=1 \"\$NOPE_UNSET_VAR\" -m pytest" "$WT" ALLOW
check "GIT_CONFIG_GLOBAL may define an alias" "cd $T/nope; GIT_CONFIG_GLOBAL=$T/althome/.gitconfig \"\$NOPE_UNSET_VAR\" wipe" "$WT" DENY "could not be resolved"
check "unresolved command word, -c include.path" "cd $T/nope; \"\$NOPE_UNSET_VAR\" -c include.path=/dev/null p" "$WT" DENY "could not be resolved"
STASH_GUARD_BUDGET=7s \
check "malformed budget override still guards" "git stash pop"                  "$WT" DENY "linked worktree"
STASH_GUARD_BUDGET=nan \
check "non-finite budget override still guards" "git stash pop"                 "$WT" DENY "linked worktree"

check "env -S \\_ separates words"          "env -S 'git\\_stash\\_clear'"   "$WT" DENY "linked worktree"
check "env -S \\_ in double quotes is a space" "env -S '\"git\\_stash\" clear'" "$WT" ALLOW
check "env -S \\c ends the string"          "env -S 'git stash list\\c clear'" "$WT" ALLOW
check "function body judged where it is called" "f() { git stash clear; }; cd $MAIN; f" "$SOLO" DENY "other worktree"
check "function called in a solo repo"      "f() { git stash clear; }; f"     "$SOLO" ALLOW
check "function keyword form, called later" "function f { git stash pop; }; cd $WT; f" "$SOLO" DENY "linked worktree"
check "called function's cd carries on"     "f() { cd $SOLO; }; f; git stash pop" "$WT" ALLOW
check "unset -f drops a function"           "f() { cd $WT; }; unset -f f; f; git stash pop" "$SOLO" ALLOW
check "skipped definition runs the command" "false && git() { :; }; git stash clear" "$WT" DENY "linked worktree"
check "skipped if-branch definition"        "if false; then git() { :; }; fi; git stash pop" "$WT" DENY "linked worktree"
check "definite definition shadows the command" "git() { :; }; git stash clear" "$WT" ALLOW
check "cd after return does not carry"      "f() { return; cd $SOLO; }; f; git stash clear" "$MAIN" DENY "could not resolve"
check "cd before return carries"            "f() { cd $SOLO; return; }; f; git stash pop" "$WT" ALLOW
check "eval return leaves the function"     "f() { eval return; cd $SOLO; }; f; git stash clear" "$MAIN" DENY "could not resolve"
check "too-deep current-shell body taints cwd" "enter() { cd $MAIN; }; eval 'eval \"eval enter\"'; git stash clear" "$SOLO" DENY "could not resolve"
check "scoped var is exported into a function" "GIT_DIR=$SOLO/.git; f() { git stash clear; }; GIT_DIR=$MAIN/.git f" "$SOLO" DENY
check "scoped export is undone after the call" "GIT_DIR=$MAIN/.git; f() { :; }; GIT_DIR=$SOLO/.git f; git stash pop" "$SOLO" ALLOW
check "CDPATH steers a relative cd"         "CDPATH=$T; cd main.wt; git stash clear" "$PLAIN" DENY "linked worktree"
mkdir -p "$PLAIN/main.wt"
check "CDPATH wins over a local match"      "CDPATH=$T; cd main.wt; git stash clear" "$PLAIN" DENY "linked worktree"
check "./ skips CDPATH"                     "CDPATH=$T; cd ./main.wt; git stash clear" "$PLAIN" ALLOW
check "uncertain CDPATH fails closed"       "true && CDPATH=$T; cd main.wt; git stash clear" "$PLAIN" DENY "could not resolve"
check "bash -c -- body"                     "bash -c -- 'git stash clear'"    "$WT" DENY "linked worktree"
check "bash -c with options after it"       "bash -c -e -o pipefail 'git stash pop'" "$WT" DENY "linked worktree"
mkdir -p "$T/althome"; git config -f "$T/althome/.gitconfig" alias.wipe 'stash clear'
check "scoped HOME reaches the alias probe" "HOME=$T/althome git wipe"        "$WT" DENY "linked worktree"
mkdir -p "$T/xdg/git"; git config -f "$T/xdg/git/config" alias.wipe2 'stash clear'
check "scoped XDG_CONFIG_HOME alias probe"  "HOME=$T/nohome XDG_CONFIG_HOME=$T/xdg git wipe2" "$WT" DENY "linked worktree"
check "XDG dir without the alias"           "HOME=$T/nohome XDG_CONFIG_HOME=$T/noxdg git wipe2" "$WT" ALLOW
check "alias with an unresolved -C target"  "git -C \"\$(printf $MAIN)\" wipe" "$SOLO" DENY "could not resolve"
check "real command with unresolved -C"     "git -C \"\$(printf $MAIN)\" submodule status" "$SOLO" ALLOW
check "alias after an uncertain cd"         "cd $MAIN || true; git wipe"      "$SOLO" DENY "could not resolve"
check "alias chain past the depth bound"    "git -c alias.a=b -c alias.b=c -c alias.c=d -c alias.d=e -c 'alias.e=stash clear' a" "$WT" DENY "nested too deeply"
check "deep alias chain ending in a builtin" "git -c alias.a=b -c alias.b=c -c alias.c=d -c alias.d=status a" "$WT" ALLOW
check "bash -c forwards \"\$@\""             "bash -c '\"\$@\"' _ git stash clear" "$WT" DENY "linked worktree"
check "bash -c forwards \$@ into git"        "bash -c 'git \"\$@\"' _ stash pop" "$WT" DENY "linked worktree"
check "sh -c forwards \$1 as the command"    "sh -c '\$1 stash pop' _ git"     "$WT" DENY "linked worktree"
check "bash -c forwards a read-only stash"   "bash -c '\"\$@\"' _ git stash list" "$WT" ALLOW
check "bash -c echoes forwarded args"        "bash -c 'echo \"\$@\"' _ git stash pop" "$WT" ALLOW
check "uncertain HOME fails the alias closed" "true && export HOME=$T/althome; git wipe" "$WT" DENY "could not resolve"
check "uncertain HOME, builtin"              "true && export HOME=$T/althome; git status" "$WT" ALLOW
check "export before assignment reaches git" "export GIT_DIR; GIT_DIR=$MAIN/.git; git stash clear" "$SOLO" DENY "other worktree"
check "unset drops an export made unset"     "export GIT_DIR; unset GIT_DIR; GIT_DIR=$MAIN/.git; git stash clear" "$SOLO" ALLOW
check "uncertain export before assignment"   "false && export GIT_DIR; GIT_DIR=$MAIN/.git; git stash clear" "$SOLO" DENY "may not have run"
check "GIT_CONFIG does not hide an alias"    "GIT_CONFIG=/dev/null git shelf2" "$WT" DENY "linked worktree"
check "escaped space keeps # in its word"    "echo file\\ #1; git stash pop"   "$WT" DENY "linked worktree"
check "escaped space # inside \$(...)"        "x=\$(echo a\\ #b; git stash pop)" "$WT" DENY "linked worktree"
check "skipped cd before && is not taken"   "true || cd $SOLO && git stash pop" "$WT" DENY "could not resolve"
check "cd && stash uses the cd target"      "cd $SOLO && git stash pop"       "$WT" ALLOW
if [ "$(id -u)" -ne 0 ]; then
  mkdir -p "$T/noenter"; chmod 000 "$T/noenter"
  check "cd into an unenterable dir fails"  "cd $T/noenter; git stash pop"    "$WT" DENY "could not resolve"
  chmod 755 "$T/noenter"
fi
check "for binds its one value"             "W=$SOLO; for W in $WT; do git -C \"\$W\" stash pop; done" "$PLAIN" DENY "linked worktree"
check "for over several values is uncertain" "W=$SOLO; for W in $SOLO $WT; do git -C \"\$W\" stash pop; done" "$PLAIN" DENY "may not have run"
check "for over a solo repo"                "for W in $SOLO; do git -C \"\$W\" stash pop; done" "$PLAIN" ALLOW
check "glob -C target is unresolved"        "git -C main.w* stash pop"        "$T" DENY "could not resolve"
check "brace -C target is unresolved"       "git -C {main.wt,} stash pop"     "$T" DENY "could not resolve"
check "glob -C, read-only stash"            "git -C main.w* stash list"       "$T" ALLOW
check "worktree add before a solo stash"    "git -C $SOLO worktree add --detach $T/new HEAD && git -C $SOLO stash" "$PLAIN" DENY "worktree add"
check "worktree add after the stash"        "git -C $SOLO stash; git -C $SOLO worktree add --detach $T/new HEAD" "$PLAIN" ALLOW
check "here string to a script is data"     "bash read-line.sh <<< 'git stash pop'" "$WT" ALLOW
check "here string to bash -s is the script" "bash -s <<< 'git stash pop'"    "$WT" DENY "linked worktree"
check "heredoc to a script is data"         $'bash read.sh <<EOF\ngit stash pop\nEOF' "$WT" ALLOW

# --- case arms, child-shell $PWD, subsection / shell aliases, xargs input,
#     command -v and alias writes
check "case arm cd stays in its arm"        "case x in a) cd $SOLO;; *) git stash clear;; esac" "$WT" DENY "linked worktree"
check "multi-line case arm cd stays"        $'case x in\n  a) cd '"$SOLO"$';;\n  # note\n  *) git stash clear;;\nesac' "$WT" DENY "linked worktree"
check "next case arm starts afresh"         "case x in a) cd $WT;; *) git stash pop;; esac" "$SOLO" ALLOW
check "case arm cd is uncertain after esac" "case x in a) cd $SOLO;; esac; git stash clear" "$WT" DENY "could not resolve"
check "case ;& arm may fall through"        "case x in a) cd $SOLO;& b) git stash clear;; esac" "$WT" DENY "could not resolve"
check "case extglob pattern parens"         "case x in @(a|b)) cd $SOLO;; *) git stash clear;; esac" "$WT" DENY "linked worktree"
check "case pattern ) is no subshell close" "(case x in x) ;; esac; cd $SOLO); git stash clear" "$WT" DENY "linked worktree"
check "case (pattern) is no subshell open"  "(case x in (a) cd $SOLO;; esac; git stash clear)" "$WT" DENY "could not resolve"
check "case a|b pattern is no pipe"         "case x in a|b) git stash pop;; esac" "$WT" DENY "linked worktree"
check "case arm heredoc stays data"         $'case x in\n a) cat <<EOF;;\ngit stash pop\nEOF\nesac\ngit status' "$WT" ALLOW
check "case arm heredoc fed to bash"        $'case x in\n a) bash <<EOF;;\ngit stash pop\nEOF\nesac' "$WT" DENY "linked worktree"
check "nested case arm cd stays"            "case x in a) case y in b) cd $SOLO;; esac;; *) git stash clear;; esac" "$WT" DENY "linked worktree"
check "read-only stash in a case arm"       "case \$X in a) git stash list;; esac" "$WT" ALLOW
check "env -C child shell \$PWD"            "env -C $WT bash -c 'git -C \"\$PWD\" stash clear'" "$SOLO" DENY "linked worktree"
check "env -C child sh cd \$PWD"            "env -C $WT sh -c 'cd \"\$PWD\" && git stash pop'" "$SOLO" DENY "linked worktree"
check "child shell keeps its own \$PWD"     "bash -c 'git -C \"\$PWD\" stash clear'" "$SOLO" ALLOW
check "env -C unknown dir, child \$PWD"     "env -C \"\$NOPE_UNSET\" bash -c 'git -C \"\$PWD\" stash pop'" "$SOLO" DENY "could not resolve"
g -C "$MAIN" config alias.pw '!git -C "$PWD" stash clear'
check "shell alias \$PWD is its top level"  "git -C $WT pw"                   "$SOLO" DENY "linked worktree"
check "-c subsection alias runs a stash"    "git -c 'alias.sv.command=stash clear' sv" "$WT" DENY "linked worktree"
g -C "$MAIN" config alias.shelf3.command 'stash pop'
check "configured subsection alias"         "git shelf3"                      "$WT" DENY "linked worktree"
check "subsection alias, read-only"         "git -c alias.sl.command='stash list' sl" "$WT" ALLOW
check "later plain alias wins"              "git -c alias.zz.command='stash clear' -c alias.zz=status zz" "$WT" ALLOW
check "later subsection alias wins"         "git -c alias.zz=status -c alias.zz.command='stash clear' zz" "$WT" DENY "linked worktree"
check "subsection name is case-sensitive"   "git -c alias.ZQ.command='stash clear' zq" "$WT" ALLOW
check "subsection name with a space"        "git -c 'alias.a b.command=stash clear' 'a b'" "$WT" DENY "linked worktree"
check "unresolved command word, -c subsection" "cd $T/nope; \"\$NOPE_UNSET_VAR\" -c alias.p.command='stash pop' p" "$WT" DENY "could not be resolved"
g -C "$MAIN" config alias.bx '!bash -c "$1"'
check "shell alias binds \$1"               "git bx 'git stash clear'"        "$WT" DENY "linked worktree"
check "shell alias \$1, read-only"          "git bx 'git stash list'"         "$WT" ALLOW
check "xargs input is git's subcommand"     "echo stash clear | xargs git"   "$WT" DENY "<xargs input>"
check "xargs -I word is unresolved"         "echo stash | xargs -I{} git {} clear" "$WT" DENY "could not be resolved"
check "xargs -I -C target is unresolved"    "echo d | xargs -I{} git -C {} stash clear" "$WT" DENY "could not resolve"
check "xargs -I -C, real command"           "echo d | xargs -I{} git -C {} status" "$WT" ALLOW
check "xargs into git add"                  "ls | xargs git add"              "$WT" ALLOW
check "xargs into a read-only stash"        "echo x | xargs git stash list"   "$WT" ALLOW
check "xargs input, solo repo"              "echo clear | xargs git stash"    "$SOLO" ALLOW
check "xargs fills a later \$N"             "echo a b stash | xargs sh -c 'git \$3 clear' _" "$WT" DENY "linked worktree"
check "xargs --config-env value"            "echo k | xargs -I@ git --config-env @ x" "$WT" DENY "could not resolve"
check "command -v cd runs no cd"            "command -v cd $SOLO; git stash clear" "$WT" DENY "linked worktree"
check "command -pv cd runs no cd"           "command -pv cd $SOLO; git stash clear" "$WT" DENY "linked worktree"
check "command -v git stash is a lookup"    "command -v git stash pop"        "$WT" ALLOW
check "command -V git stash is a lookup"    "command -V git stash"            "$WT" ALLOW
check "alias written earlier in the command" "git config alias.zap 'stash clear'; git zap" "$WT" DENY "earlier in this command"
check "alias written by a child shell"      "bash -c \"git config alias.zap 'stash clear'\"; git zap" "$WT" DENY "earlier in this command"
check "alias written by git config set"     "git config set alias.zap 'stash clear' && git zap" "$WT" DENY "earlier in this command"
check "include written earlier"             "git config -f .git/config include.path /x; git zap" "$WT" DENY "earlier in this command"
check "alias written in a loop's pass"      "for i in 1 2; do git zap; git config alias.zap 'stash clear'; done" "$WT" DENY "earlier in this command"
check "alias written, solo repo"            "git config alias.zap 'stash clear'; git zap" "$SOLO" DENY "earlier in this command"
check "alias read is no write"              "git config --get alias.zap; git config alias.zap; git zap" "$WT" ALLOW
check "non-alias config write"              "git config user.name x; git zap" "$WT" ALLOW
check "alias write, then a builtin"         "git config alias.co checkout; git status" "$WT" ALLOW

# --- CodeRabbit round 8: each construct below is denied (fail closed) or
#     modelled exactly; a false deny of a mutating stash costs nothing
check "case arm inside quoted \$(...)"       "x=\"\$(case a in a) git stash pop;; esac)\"" "$WT" DENY "linked worktree"
check "case arm inside \$(...), read-only"   "x=\"\$(case a in a) git stash list;; esac)\"" "$WT" ALLOW
check "case word in \$(...) is no case"      "x=\"\$(echo case in x)\"; git status" "$WT" ALLOW
deep=$(python3 -c 'print("echo $(" * 1000 + "git stash pop" + ")" * 1000)')
check "deep \$(...) nesting fails closed"    "$deep"                           "$WT" DENY "nested too deeply"
deep=$(python3 -c 'print("echo $(" * 1000 + "echo hi" + ")" * 1000)')
check "deep \$(...) nesting, no stash"       "$deep"                           "$WT" ALLOW
mkdir -p "$T/pool"; ln -s "$WT" "$T/pool/solo"
check "CDPATH= prefix on cd applies"        "CDPATH=$T/pool cd solo; git stash pop" "$T" DENY "linked worktree"
check "CDPATH= on another command is gone"  "CDPATH=$T/pool true; cd solo; git stash pop" "$T" ALLOW
check "HOME= prefix on a bare cd applies"   "HOME=$WT cd; git stash pop"      "$SOLO" DENY "linked worktree"
check "written ! alias may run elsewhere"   "git config alias.zap '!git -C $WT stash clear'; git zap" "$SOLO" DENY "earlier in this command"
check "env -S \${VAR} becomes an env option" "D=-C env -S '\${D} $WT git stash pop'" "$SOLO" DENY "linked worktree"
check "env -S uncertain \${VAR}"             "if true; then export D=-C; fi; env -S '\${D} $WT git stash pop'" "$SOLO" DENY "could not resolve"
check "env -S \${VAR}, solo repo"            "D=-C env -S '\${D} $SOLO git stash pop'" "$WT" ALLOW
check "xargs -I keeps --git-dir="           "echo x | xargs -I{} git --git-dir={} stash clear" "$SOLO" DENY "could not resolve"
check "bash -s operands fill \"\$@\""         $'bash -s git stash pop <<\'EOF\'\n"$@"\nEOF' "$WT" DENY "linked worktree"
check "bash -s operands, read-only"         $'bash -s git stash list <<\'EOF\'\n"$@"\nEOF' "$WT" ALLOW
ln -s "$WT" "$T/\$DEST"
check "single-quoted \$ in -C is literal"    "DEST=$SOLO; git -C '\$DEST' stash pop" "$T" DENY "quoted"
check "double-quoted \$ in -C expands"       "DEST=$SOLO; git -C \"\$DEST\" stash pop" "$T" ALLOW
check "cd with a failing redirection"       "cd $SOLO > $T/missing/log; git stash pop" "$WT" DENY "could not resolve"
check "cd >/dev/null still lands"           "cd $SOLO >/dev/null && git stash pop" "$WT" ALLOW
check "reason says to verify HEAD first"    "git stash"                       "$WT" DENY "still prints that sha"
check "uncertain discovery var fails closed" "if true; then export GIT_DISCOVERY_ACROSS_FILESYSTEM=1; fi; git stash pop" "$SOLO" DENY "may not have run"

# --- CodeRabbit round 9
check "( )-bodied function is recorded"     "save() ( git stash push ); cd $WT; save" "$SOLO" DENY "linked worktree"
check "( )-bodied function's cd is scoped"  "f() ( cd $WT ); f; git stash pop" "$SOLO" ALLOW
check "function run by trap still judged"   "cleanup() { git stash pop; }; trap cleanup EXIT" "$WT" DENY "linked worktree"
check "GNU env -S reads a var before -u"    "D=-C env -u D -S '\${D} $WT git stash pop'" "$SOLO" DENY "GNU and BSD"
check "cd 2>&9 may fail (fd 9 closed)"      "cd $SOLO 2>&9; git stash pop"   "$WT" DENY "could not resolve"
check "cd >1 is a file named 1"             "cd $SOLO >1; git stash pop"     "$WT" DENY "could not resolve"
check "cd >&2 / 2>&- still land"            "cd $SOLO >&2 2>&-; git stash pop" "$WT" ALLOW
check "git \$opts splits into options"       "opts='-C $WT'; git \$opts stash pop" "$SOLO" DENY "linked worktree"
check "git \$opts, solo target"              "opts='-C $SOLO'; git \$opts stash pop" "$WT" ALLOW
check "worktree add, then -C the new path"  "git worktree add --detach $T/new.wt HEAD && git -C $T/new.wt stash pop" "$SOLO" DENY "may create"
check "export with a failing redirection"   "export GIT_DIR=$SOLO/.git >$T/missing/log; git stash pop" "$WT" DENY "may not have run"
check "unset with a failing redirection"    "export GIT_DIR=$MAIN/.git/worktrees/main.wt; unset GIT_DIR >$T/missing/log; git stash pop" "$SOLO" DENY "may not have run"
check "export >/dev/null still exports"     "export GIT_DIR=$SOLO/.git >/dev/null; git stash pop" "$WT" ALLOW
check "local does not resolve the outer var" "dest=$SOLO; f() { local dest=$WT; git -C \"\$dest\" stash pop; }; f" "$SOLO" DENY "may not have run"
check "heredoc ) does not close \$(...)"     $'out="$(cat <<\'EOF\'\n)\nEOF\ngit stash pop\n)"' "$WT" DENY "linked worktree"
check "commit heredoc holding 1) and it's"  $'git commit -m "$(cat <<\'EOF\'\n1) fix it\'s\nEOF\n)" && git stash pop' "$WT" DENY "linked worktree"
check "commit heredoc, data only"           $'git commit -m "$(cat <<\'EOF\'\n1) never git stash pop\nEOF\n)"' "$WT" ALLOW
check "arithmetic << is no heredoc"         'x=$((1<<2)); git stash pop'     "$WT" DENY "linked worktree"
check "unquoted delimiter joins \\-newline"  $'cat <<EOF\nE\\\nOF\ngit stash pop\nEOF' "$WT" DENY "linked worktree"
check "quoted delimiter does not join"      $'cat <<\'EOF\'\nE\\\nOF\ngit stash pop\nEOF' "$WT" ALLOW
check "alias body keeps a quoted \$1"        "git -c 'alias.say=!printf \"%s\\n\" \"\$1\"' say ok" "$WT" ALLOW
check "quoted \$1 alias is still judged"     "git -c 'alias.say=!git \"\$1\" pop' say stash" "$WT" DENY "linked worktree"
check "continue carries its state"          "for i in 1 2; do git stash clear; cd $WT; if true; then continue; fi; cd $SOLO; done" "$SOLO" DENY "could not resolve"
check "break leaves the loop's state"       "for i in 1; do cd $WT; break; cd $SOLO; done; git stash pop" "$SOLO" DENY "could not resolve"
check "bash -c 'git \"\$@\"' runs its operands" "bash -c 'git \"\$@\"' _ stash list" "$WT" ALLOW
check "bash -c 'git \"\$@\"', mutating"       "bash -c 'git \"\$@\"' _ stash pop" "$WT" DENY "linked worktree"
check "reason says to stop on extra staged" "git stash"                       "$WT" DENY "lists only those paths"
# Shims exec the real git through a path with a space, so an unquoted one breaks.
sq() { printf "'%s'" "$(printf %s "$1" | sed "s/'/'\\\\''/g")"; }
mkdir -p "$T/bin" "$T/real git" "$T/evil"; ln -s "$(command -v git)" "$T/real git/git"; REAL_GIT="$T/real git/git"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> %s\nexec %s "$@"\n' "$(sq "$T/argv.log")" "$(sq "$REAL_GIT")" > "$T/bin/git"; chmod +x "$T/bin/git"
PATH="$T/bin:$PATH" \
check "--config-env value stays off argv"   "TOK=s3cr3t-token git --config-env=http.extraHeader=TOK zz" "$WT" ALLOW
if grep -q s3cr3t-token "$T/argv.log"; then fail=$((fail+1)); echo "FAIL: --config-env value reached a probe argv"; else pass=$((pass+1)); echo "ok   PRIV   --config-env value kept off probe argv"; fi
grep -q 'config-env=http.extraHeader=STASH_GUARD_CONFIG_0' "$T/argv.log" && { pass=$((pass+1)); echo "ok   PRIV   --config-env passed by a name of the hook's"; } || { fail=$((fail+1)); echo "FAIL: --config-env not passed to the probe by the hook's name"; }
PATH="$T/bin:$PATH" \
check "--config-env alias via env, still judged" "A='stash clear' git --config-env=alias.s=A s" "$WT" DENY "linked worktree"
printf '#!/bin/sh\n: > %s\nexit 1\n' "$(sq "$T/evil.ran")" > "$T/evil/git"; chmod +x "$T/evil/git"
check "--config-env=k=PATH picks no probe git" "PATH=$T/evil git --config-env=x.y=PATH zz" "$WT" ALLOW
if [ -e "$T/evil.ran" ]; then fail=$((fail+1)); echo "FAIL: a request's PATH chose the probe's git"; else pass=$((pass+1)); echo "ok   PRIV   a request's PATH never picks the probe's git"; fi
printf '#!/bin/sh\necho "D=$GIT_DISCOVERY_ACROSS_FILESYSTEM" >> %s\nexec %s "$@"\n' "$(sq "$T/disc.log")" "$(sq "$REAL_GIT")" > "$T/bin/git"
PATH="$T/bin:$PATH" \
check "discovery var with a solo repo"      "GIT_DISCOVERY_ACROSS_FILESYSTEM=1 git stash pop" "$SOLO" ALLOW
grep -q '^D=1$' "$T/disc.log" && { pass=$((pass+1)); echo "ok   ENV    the probe discovers the repo as git would"; } || { fail=$((fail+1)); echo "FAIL: GIT_DISCOVERY_ACROSS_FILESYSTEM did not reach the probe"; }
printf '#!/bin/sh\nfor a; do [ "$a" = worktree ] && exit 1; done\nexec %s "$@"\n' "$(sq "$REAL_GIT")" > "$T/bin/git"
PATH="$T/bin:$PATH" \
check "failed worktree probe fails closed"  "git stash"                       "$MAIN" DENY "could not list"

printf '#!/bin/sh\nfor a; do [ "$a" = rev-parse ] && exit 1; done\nexec %s "$@"\n' "$(sq "$REAL_GIT")" > "$T/bin/git"
PATH="$T/bin:$PATH" \
check "failed repo probe fails closed"      "git stash"                       "$SOLO" DENY "could not probe"

# The deny must come from the second probe running out of the shared budget:
# both probes start, and the hook waits out the budget, so an immediate
# lookup failure (whose reason also says "failed or timed out") cannot pass.
printf '#!/bin/sh\necho x >> %s\nsleep 0.6\nexec %s "$@"\n' "$(sq "$T/deadline.log")" "$(sq "$REAL_GIT")" > "$T/bin/git"
t0=$(python3 -c 'import time; print(time.time())')
PATH="$T/bin:$PATH" STASH_GUARD_BUDGET=1 \
check "probes share one deadline"           "git -c alias.a=b -c 'alias.b=stash pop' a" "$SOLO" DENY "timed out"
probes=$(wc -l < "$T/deadline.log" | tr -d ' ')
if [ "$probes" = 2 ] && python3 -c 'import sys, time; sys.exit(time.time() - float(sys.argv[1]) < 0.9)' "$t0"; then
  pass=$((pass+1)); echo "ok   TIME   the deadline, not a lookup error, denied it"
else fail=$((fail+1)); echo "FAIL: probes share one deadline: $probes probe(s), not the 2 a timeout takes"; fi

# --- the main checkout is guarded too while other worktrees exist
check "main tree with a linked wt attached" "git stash"                       "$MAIN" DENY "other worktree"
check "-C main from elsewhere"              "git -C $MAIN stash pop"          "$PLAIN" DENY

# --- read-only and unrelated: allowed
check "git stash list"                      "git stash list"                  "$WT" ALLOW
check "git stash show -p"                   "git stash show -p stash@{0}"     "$WT" ALLOW
check "git status"                          "git status"                      "$WT" ALLOW
check "quoted git stash in echo"            "echo \"git stash pop\""          "$WT" ALLOW
check "single-quoted in grep"               "grep -rn 'git stash' ."          "$WT" ALLOW
check "commit message mentions it"          "git commit -m \"never git stash\"" "$WT" ALLOW
check "log --grep stash"                    "git log --grep stash"            "$WT" ALLOW
check "comment only"                        "ls # then git stash pop"         "$WT" ALLOW
check "heredoc body"                        $'cat > n.txt <<\'EOF\'\ngit stash pop\nEOF\nls' "$WT" ALLOW
check "solo repo (no worktrees)"            "git stash"                       "$SOLO" ALLOW
check "-C solo from inside a wt"            "git -C $SOLO stash pop"          "$WT" ALLOW
check "not a git repo"                      "git stash"                       "$PLAIN" ALLOW
check "stash word as a branch name"         "git checkout stash"              "$WT" ALLOW
check "empty command"                       ""                                "$WT" ALLOW

# --- non-Bash tool ignored
out=$(j Read "git stash pop" "$WT" | python3 "$HOOK" 2>/dev/null); rc=$?
if [ $rc -eq 0 ] && [ -z "$out" ]; then pass=$((pass+1)); echo "ok   ALLOW  non-Bash tool ignored"; else fail=$((fail+1)); echo "FAIL: non-Bash tool ignored (rc=$rc)"; fi

# --- garbage stdin never crashes the hook
out=$(printf 'not json' | python3 "$HOOK" 2>/dev/null); rc=$?
if [ $rc -eq 0 ] && [ -z "$out" ]; then pass=$((pass+1)); echo "ok   ALLOW  garbage stdin"; else fail=$((fail+1)); echo "FAIL: garbage stdin (rc=$rc)"; fi

echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]

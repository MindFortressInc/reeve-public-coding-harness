#!/usr/bin/env python3
"""PreToolUse(Bash) hook: deny mutating `git stash` where refs/stash is shared.

`refs/stash` is ONE ref per repository, shared by every worktree of a clone.
With parallel agents each in their own worktree, a `git stash pop` takes
whatever is on top of that shared stack, which is routinely a sibling's WIP.
A `git stash` on a clean tree saves nothing, so the pop after it is ALWAYS
someone else's entry. We recorded 13+ cross-agent collisions this way; one
victim's work survived only as a dangling commit found with `git fsck`.

Denied: any stash subcommand except `list` / `show` (push, pop, apply, drop,
save, clear, store, create, branch, bare `git stash`, `git stash -u`, ...)
when its target repo is
  * a linked worktree (`--git-dir` != `--git-common-dir`), or
  * the main checkout while another worktree is attached (same shared stack).
A repo with no other worktrees, and a non-repo, are left alone.

The target is resolved per segment: the hook's cwd (or inherited GIT_DIR),
then any `cd` earlier in the chain (scoped to its `( )` / `$(...)` / backquote
subshell, pipeline element or backgrounded list; unknown once an and-or list,
`if` / loop / `case` branch or function body it may not have run in ends;
`pushd -n` leaves it; a `cd` with a redirection that may fail (any but
/dev/null or an fd dup) may not have run; each `case` arm starts from the
state before the `case`, one after `;&` / `;;&` maybe from the last arm's;
`$PWD` / `$OLDPWD` follow it, and a child shell's `$PWD` names where it
starts; `CDPATH=` / `HOME=` prefixes on the `cd` itself apply), then
`env -C` / `sudo -D` (each relative to the last), then the invocation's own
`-C` (all followed through symlinks the way chdir does) and `--git-dir` /
`--work-tree` (left for git to resolve after every `-C`);
VAR=val prefixes, `unset` and `env -u` / `-i` shape the GIT_* vars the probe
sees (git's repo discovery vars included), a plain assignment reaches git or a
child shell only once exported, and
an export that may not have run leaves its var uncertain. Quote-, comment-,
redirection- and heredoc-aware, so "git stash" inside an echo/grep/commit
message or a data heredoc is not a stash (but a `$(...)` in an unquoted
heredoc is), and `2>/dev/null git stash` is. `bash -c` / `sh -c` bodies
(with their prefix assignments and `env -C`), a heredoc or here string fed to
a shell (in that command's context; `bash -s` operands fill its `$1` ...),
`eval` bodies (in the caller's scope, so
their cd/exports carry on), `$(...)` / backquotes (also inside double quotes,
and holding a `case`), `env -S` / `--split-string` commands (their `${VAR}`
expanded first) and git aliases (`alias.x` or
`alias.x.command`, via `-c`, `--config-env` or configured; `!` ones as shell
bodies run from the worktree's top level, their arguments in `$1` / `"$@"`)
are scanned too, and after a `git config` that may write an alias every later
alias is denied as a possible stash (it may run anywhere); a body is judged
both with the caller's $VARs expanded first and with the body expanding them
itself, since quote removal hides which
happens. `$VAR` command and subcommand words are expanded before matching.
An arithmetic `$(( ))` is not a command: only the substitutions inside it
(and its text, if it may spell a stash) are scanned.
`env` / shells / `eval` / wrappers (`time -p`, `command -p`, `sudo -u X`,
`exec -a X`, `timeout`, `nice`, `stdbuf`, `ionice`, `setsid`, `xargs`) match
by basename like git, their options consumed (the arguments xargs appends, or
its `-I` strings, are unresolvable); `command -v` / `-V` runs nothing;
`command` / `builtin` skip shell functions, and the program launchers skip
functions and run `cd` / `export` / `eval` in a child, not this shell. A
function call fills the body's `$1` / `"$@"` with its arguments. A `for` over
one word binds its variable (over several, it is uncertain). A loop's later
passes are rescanned from its merged loop-carried state until that state
settles. A `git worktree add` earlier in the command counts as another
worktree for a later stash (in any repo: a false deny costs nothing).
This guard stops ACCIDENTAL mutating stashes by agents; it is no sandbox
against an adversary. Denying a mutating stash wrongly costs nothing (every
brief bans `git stash` anyway), so a construct it cannot model is denied, not
modelled, and only a false allow is a defect (a false deny of `stash list` /
`show` or of a non-stash command is one too).
A mutating stash whose target cannot be resolved (an unknown $VAR, a `$(...)`,
a path word a glob or brace may expand or that holds a quoted `$`, a `cd`
into a missing or unenterable directory, a failed or timed-out repo, worktree
or alias probe, an unresolvable command or subcommand word or `env -S`
string, shell bodies or aliases nested past the scan depth, a command nested
past the parse depth) is denied.
Known gaps: a heredoc piped into a shell (`cat <<EOF | bash`) is not seen; an
alias written by anything but `git config` (`>> .git/config`) is not seen; a
cd inside a `{ ...; }` group used as a pipeline element is not undone; an
unresolvable command word (`$PY -m pytest`) is checked for configured aliases
only where its repo is known, so `$G shelf` after an uncertain cd is not seen;
an unresolvable command word naming a wrapper or shell (`"$SUDO" git stash`,
`"$SH" -c ...`) is judged as git, so its command is not seen; bash's
arithmetic evaluation of a variable holding `a[$(...)]` is not seen; a
`bash -s` heredoc or here string is judged as its script even when a later
redirection or another fd number means the shell reads something else (a
false deny only). A crash exits non-zero, which Claude Code treats as a
non-blocking error (fail open), like the other Bash hooks here; a command
nested too deeply to parse is denied instead when it may spell a stash.
"""
import json
import os
import re
import shlex
import subprocess
import shutil
import sys
import time

READ_ONLY = {"list", "show"}
SHELLS = {"bash", "sh", "zsh", "dash"}
PREFIX_WORDS = {"{", "}", "!", "then", "do", "else", "elif", "if", "while",
                "until"}
OPENERS = {"if", "while", "until", "for", "select", "case"}
LOOPS = {"while", "until", "for", "select"}
STATE_BUILTINS = {"cd", "pushd", "popd", "export", "unset", "return"}
LOOP_PASSES = 8                           # loop-carried state converges well before this
CLOSERS = {"fi", "done", "esac"}
BLOCK_WORDS = OPENERS | CLOSERS | {"then", "do", "else", "elif", "{", "}", "!"}
SUDO_LONG_WITH_VALUE = {"--user", "--group", "--prompt", "--close-from",
                        "--chdir", "--role", "--type", "--other-user",
                        "--command-timeout", "--host"}
# Wrappers that run a later word as the command (matched by basename):
# (short options taking a value, long options taking a value, positional
# words before the command). Their other options are flags. `time` is a
# keyword and keeps shell lookup; `command` / `builtin` skip shell functions;
# every other wrapper (and env) execs a program, so neither a function nor a
# builtin like `cd` / `export` / `eval` runs in this shell.
WRAPPERS = {"time": ("", (), 0), "nohup": ("", (), 0),
            "command": ("", (), 0), "builtin": ("", (), 0),
            "setsid": ("", (), 0), "exec": ("a", (), 0),
            "sudo": ("ugpCDrtUTR", SUDO_LONG_WITH_VALUE, 0),
            "timeout": ("sk", ("--signal", "--kill-after"), 1),
            "nice": ("n", ("--adjustment",), 0),
            "stdbuf": ("ioe", ("--input", "--output", "--error"), 0),
            "ionice": ("cnpt", ("--class", "--classdata", "--pid", "--pgid",
                                "--uid"), 0),
            "xargs": ("EIJRSdLnPsa", ("--arg-file", "--delimiter", "--max-lines",
                                   "--max-args", "--max-procs", "--max-chars",
                                   "--process-slot-var"), 0)}
GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace",
                       "--super-prefix", "--config-env"}
# Long-standing git builtins: git ignores an alias that shadows one, so these
# never need an alias lookup.
GIT_BUILTINS = set("""add am annotate apply archive bisect blame branch bundle
    cat-file checkout cherry cherry-pick clean clone commit config
    count-objects describe diff fetch for-each-ref format-patch fsck gc grep
    hash-object help init log ls-files ls-remote ls-tree merge merge-base mv
    name-rev notes prune pull push range-diff rebase reflog remote reset
    restore revert rev-list rev-parse rm shortlog show show-branch show-ref
    sparse-checkout status switch symbolic-ref tag update-ref var version
    worktree""".split())
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
REDIR_OP = re.compile(r"&>>?|<<<|<<-|<<|<>|<&|<|>>|>&|>\||>")
FD_WORD = re.compile(r"\d+|\{[A-Za-z_][A-Za-z0-9_]*\}")
HEREDOC = re.compile(r"<<(-?)[ \t]*((?:'[^']*'|\"[^\"]*\"|\\.|[^\s;&|<>()'\"\\])+)")
NOT_A_REPO = re.compile(r"not a git repository|cannot change to|must be run in a work tree")
SHELL_C = re.compile(r"-[A-Za-z]*c[A-Za-z]*")
FUNC_DEF = re.compile(r"\s*(?:function\s+)?[^\s'\"\\$`=;&|<>(){}]+\s*")
VAR = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
GLOB = re.compile(r"[*?]|\[.*\]|\{.*(?:,|\.\.).*\}")  # pathname / brace expansion
# Env vars that can define config (an alias) without a repo: not e.g. GIT_CONFIG_NOSYSTEM.
ALIAS_ENV = re.compile(r"GIT_CONFIG_(?:COUNT|KEY_\d+|VALUE_\d+|PARAMETERS|GLOBAL|SYSTEM)")
POSITIONAL = re.compile(r'"\$(?:@|\{@\})"|\$(?:\{(\d+|[@*])\}|(\d|[@*]))')
SHELL, NOFUNC, EXTERNAL = 0, 1, 2         # how a command word is looked up
SUBST = "$(...)"                          # opaque stand-in for a $(...)
OPEN, CLOSE = "\0(", "\0)"                 # subshell scope markers from segments()
AND, OR, SEP = "\0&", "\0|", "\0;"         # && / || / (; newline) from segments()
PIPE, BG = "\0p", "\0b"                    # | or |& / a lone & from segments()
UNCERTAIN = "\0?"                         # env value: a step that may not have run set it
LOCAL = "\0l"                             # env key prefix: that var is set but not exported
EXPORT = "\0x"                            # env key prefix: that var is exported but not set
MAX_DEPTH = 3                             # nested shell/eval bodies scanned
MAX_NEST = 50                             # nested $(...) / backquotes parsed (no agent nests
                                          # near this; past it the parse would recurse unbounded)
GIT_TARGET = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")
CONFIG_HOME = ("HOME", "XDG_CONFIG_HOME")  # select git's global config file
DISCOVERY = ("GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM")  # how git finds a repo
FUNC = "\0f"                              # env key prefix: a shell function's bodies
                                          # (None among them: it may be undefined)
ARM_END, ARM_FALL = "\0e", "\0E"          # a case arm's `;;` / its `;&` or `;;&`
XARGS = "\0xargs-input"                  # a word xargs fills in from its input
ALIAS_WRITE = "\0a"                      # env key: a `git config` here may write an alias
ALIAS_WRITTEN = []                        # every such write: it lands on disk, so it
                                          # outlives the subshell or child that made it
CASE_WORD = re.compile(r"(case|esac)(?![^\s;&|()<>])")
CMD_POS = re.compile(r"(?:^|[;&|(\n])[ \t]*(?:(?:then|do|else|elif|if|while|until|[{!])[ \t]+)*$")
ENV_S_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
SAFE_REDIR = re.compile(r"/dev/null|-|\d+")    # a redirection operand that cannot fail
CASE_HEAD = re.compile(r"\s*(?:(?:[{!]|then|do|else|elif|if|while|until)\s+)*case\s+"
                       r"(?:'[^']*'|\"(?:\\.|[^\"\\])*\"|\\.|[^\s'\"\\])+\s+in")
# `git config` options that read, never write, and those taking a value
CONFIG_READS = {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l",
                "--list", "--get-color", "--get-colorbool"}
CONFIG_WRITES = {"--add", "--replace-all", "--unset", "--unset-all",
                 "--rename-section", "--remove-section", "-e", "--edit"}
CONFIG_OPTS_WITH_VALUE = {"-f", "--file", "--blob", "--type", "--default",
                          "--comment", "--value", "--url"}
# Every git probe shares one budget, kept under the hook's registered 10s
# timeout: a timed-out hook blocks nothing, so the deny must come first.
try:                                      # a malformed override must not crash the hook
    BUDGET = float(os.environ.get("STASH_GUARD_BUDGET") or 7)
except ValueError:
    BUDGET = 7
if not 0 < BUDGET <= 7:                   # nan, inf, <= 0 or past the cap: the default
    BUDGET = 7
DEADLINE = time.monotonic() + BUDGET
GIT = shutil.which("git")                 # the hook's own git: never one a request's PATH picks
# Set once a `git worktree add` is seen earlier in the request: the probe ran
# before it, so a checkout it lists as solo may have a worktree by the stash.
WORKTREE_ADDED = []

ALTERNATIVES = (
    "refs/stash is ONE stack shared by every worktree of this repo, so a pop "
    "takes whatever is on top (routinely a parallel agent's WIP), and a stash "
    "on a clean tree saves nothing, so the pop after it is always someone "
    "else's entry. Safe alternatives: (1) a scratch commit on your "
    "own branch: `git add <only the paths you may change>`, check "
    "`git diff --cached --stat`, `git commit -m wip` and note its sha; later, "
    "only if `git rev-parse HEAD` on that same branch still prints that sha, "
    "`git reset --soft HEAD~1` (otherwise skip the reset); "
    "(2) run the base in its own checkout: `git worktree add --detach "
    "<scratchpad>/<unit>/base <base-sha>`; (3) read a base file: `git show "
    "<sha>:<path> > <scratchpad>/<unit>/<file>`; (4) copy files to your scratchpad "
    "and back. `git stash list` and `git stash show` stay allowed. A human who "
    "really needs a stash can run it in their own terminal."
)


class Unresolved(Exception):
    """The repo a stash targets cannot be determined statically."""


class TooDeep(Exception):
    """The command nests `$(...)` / backquotes past MAX_NEST."""


class Lit(str):
    """A word in which a `$` was quoted or escaped, so the shell expanded
    none of it there, while quote removal makes it look expandable."""


def literal_dollar(raw):
    """Whether raw word text holds a `$` inside single quotes or escaped."""
    q, i = None, 0
    while i < len(raw):
        c = raw[i]
        if q == "'":
            if c == "'":
                q = None
            elif c == "$":
                return True
        elif c == "\\":
            if raw[i + 1:i + 2] == "$":
                return True
            i += 1
        elif c == '"':
            q = None if q else '"'
        elif c == "'" and not q:
            q = "'"
        i += 1
    return False


def close_paren(s, i):
    """Index of the `)` closing the `$(` whose body starts at `i` (quote-,
    comment- and nesting-aware), or len(s) when it is never closed. The `)`
    ending a `case` pattern (`case x in a) ...;; esac`) closes nothing."""
    depth, q, n, start, esc = 1, None, len(s), i, -1
    cases = []                            # the paren depth of each open `case`
    while i < n:
        c = s[i]
        if c == "\\" and q != "'":
            i += 2
            esc = i                       # s[i - 1] is escaped: not a word break
            continue
        if q:
            if c == q:
                q = None
        elif c in ("'", '"'):
            q = c
        elif c == "#" and (i == start or (s[i - 1] in " \t\n;&|()" and i != esc)):
            nl = s.find("\n", i)         # a comment's `)` closes nothing
            if nl < 0:
                return n
            i = nl
            continue
        elif c == "(":
            depth += 1
        elif c == ")":
            if cases and cases[-1] == depth:
                i += 1                    # a pattern's `)`, at the depth its case opened
                continue
            depth -= 1
            if depth == 0:
                return i
        elif c in "ce" and i != esc and CASE_WORD.match(s, i) and \
                CMD_POS.search(s[start:i]):
            if s[i] == "c":
                cases.append(depth)
            elif cases and cases[-1] == depth:
                cases.pop()
            i += 4
            continue
        i += 1
    return n


def close_backtick(s, i):
    """Index of the backtick closing the one whose body starts at `i`, or
    len(s) when it is never closed."""
    n = len(s)
    while i < n:
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == "`":
            return i
        i += 1
    return n


def bare_close(s, i):
    """Index of the `)` closing the `(` whose body starts at `i`, counting
    every paren (no quote or comment rules), or -1 when it is never closed."""
    depth = 1
    for k in range(i, len(s)):
        depth += {"(": 1, ")": -1}.get(s[k], 0)
        if depth == 0:
            return k
    return -1


def without_substitutions(text):
    """`text` with each `$(...)` / backquote substitution replaced by `0`."""
    out, i = [], 0
    while i < len(text):
        if text[i] == "\\":
            out.append(text[i:i + 2])
            i += 2
        elif text[i] == "`":              # skip the span; never reparse it
            i = close_backtick(text, i + 1) + 1
            out.append("0")
        elif text.startswith("$(", i):
            i = close_paren(text, i + 2) + 1
            out.append("0")
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def substitution(s, i):
    """(bodies, end) of the `$(...)`, backquote or `$((...))` expansion at
    `i`: the scripts it runs. A `$((...))` is arithmetic only when the plain
    paren count (what the shell uses to find `))`) agrees with the quote-aware
    one and it holds no backslash (zsh does not count an escaped paren the
    way bash does); it then runs only the substitutions inside it, plus its
    whole text when what is left may spell a stash. Otherwise it is a
    `$( (...) )`."""
    if s[i] == "`":
        j = close_backtick(s, i + 1)
        return [re.sub(r"\\([$`\\])", r"\1", s[i + 1:j])], j + 1
    j = close_paren(s, i + 2)
    body = s[i + 2:j]
    if body[:1] == "(" and body[-1:] == ")" and "\\" not in body and \
            close_paren(body, 1) == len(body) - 1 == bare_close(body, 1) and \
            bare_close(s, i + 2) == j:
        inner = body[1:-1]
        rescan = [inner] if may_stash(without_substitutions(inner)) else []
        return expansions(inner) + rescan, j + 1
    return [body], j + 1


def expansions(text):
    """Bodies of the `$(...)` / backquote substitutions in `text`. The shell
    runs these in an unquoted heredoc even when its data is not a script."""
    out, i = [], 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "`" or text.startswith("$(", i):
            bodies, i = substitution(text, i)
            out += bodies
            continue
        i += 1
    return out


class Seg(str):
    """A command segment; `docs` lists its heredocs as (body, quoted)."""
    docs = ()


def heredoc_word(word):
    """The delimiter a heredoc word names, after quote removal."""
    try:
        return "".join(shlex.split(word, posix=True))
    except ValueError:
        return re.sub(r"[\\'\"]", "", word)


def words(seg):
    """(words, here strings, redirections) of a segment after quote removal.
    Redirections and their operands are dropped from the words wherever they
    sit (`2>/dev/null git stash` still runs git) and listed as (operator,
    operand); each `<<<` operand is kept as a here string, and a heredoc
    operator's delimiter word is dropped (its body is in seg.docs). A word
    with a quoted or escaped `$` is a Lit."""
    out, here, redirs, raw, pending = [], [], [], [], None
    i, n, q = 0, len(seg), None

    def flush():
        nonlocal raw, pending
        if not raw:
            return
        text = "".join(raw)
        w = "".join(shlex.split(text, posix=True))
        if "$" in w and literal_dollar(text):
            w = Lit(w)
        raw = []
        if pending is None:
            out.append(w)
        elif pending == "<<<":
            here.append(w)
        elif pending not in ("<<", "<<-"):
            redirs.append((pending, w))
        pending = None

    while i < n:
        c = seg[i]
        if q:
            raw.append(c)
            if c == "\\" and q == '"' and i + 1 < n:
                raw.append(seg[i + 1])
                i += 2
                continue
            if c == q:
                q = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            raw += [c, seg[i + 1]]
            i += 2
            continue
        if c in ("'", '"'):
            q = c
            raw.append(c)
        elif c in " \t\n":
            flush()
        elif c in "<>" or seg.startswith("&>", i):
            if FD_WORD.fullmatch("".join(raw)):
                raw = []                  # `2>` / `{fd}>`: the fd is not a word
            flush()
            pending = REDIR_OP.match(seg, i).group(0)
            i += len(pending)
            continue
        else:
            raw.append(c)
        i += 1
    if q:
        raise ValueError("No closing quotation")
    flush()
    return out, here, redirs


NESTING = [0]                             # $(...) / backquote bodies being parsed


def segments(s):
    """segments_at() of `s`, raising TooDeep once substitutions nest past
    MAX_NEST, before the recursion could exhaust Python's stack."""
    if NESTING[0] >= MAX_NEST:
        raise TooDeep(f"$(...) / backquotes nest more than {MAX_NEST} deep")
    NESTING[0] += 1
    try:
        return segments_at(s)
    finally:
        NESTING[0] -= 1


def segments_at(s):
    """Top-level command segments: quote-aware, comments dropped, split on
    unquoted ; & | ( ) and newlines. `( )`, `$(...)` and backquote bodies are
    bracketed by OPEN / CLOSE so judge() can scope their cd; `&&` / `||` emit
    AND / OR, `|` / `|&` PIPE, a lone `&` BG and `;` / newline SEP, so scan()
    can tell when a cd might not have run or ran in a subshell. Each segment
    is a Seg whose `docs` collects its heredoc bodies, so scan() judges them
    in the context of the command that owns them. Inside a `case`, a
    pattern and its `)` (and an optional leading `(`) are no command and no
    subshell; an arm's `;;` emits ARM_END, its `;&` / `;;&` ARM_FALL."""
    segs, buf, pending, docs = [], [], [], []
    i, n, q, esc = 0, len(s), None, -1     # esc: len(buf) right after an escape
    cases, pdepth = [], 0                 # per open case: in a pattern, or an arm body

    def emit(marker):
        nonlocal buf, docs
        seg = Seg("".join(buf))
        seg.docs = docs
        segs.extend((seg, marker))
        buf, docs = [], []

    def read_docs(i):                     # heredoc bodies follow this line
        nonlocal pending
        for strip_tabs, delim, quoted, owner in pending:
            body = []
            while i < n:
                end = s.find("\n", i)
                line = s[i:] if end < 0 else s[i:end]
                i = n if end < 0 else end + 1
                if (line.lstrip("\t") if strip_tabs else line) == delim:
                    break
                body.append(line)
            owner.append(("\n".join(body), quoted))
        pending = []
        return i

    while i < n:
        c = s[i]
        if q:
            if q == '"' and (c == "`" or s.startswith("$(", i)):
                bodies, i = substitution(s, i)
                segs += [x for b in bodies for x in (OPEN, *segments(b), CLOSE)]
                buf.append(SUBST)
                continue
            buf.append(c)
            if c == "\\" and q == '"' and i + 1 < n:
                buf.append(s[i + 1])
                i += 2
                continue
            if c == q:
                q = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            if s[i + 1] == "\n":          # line continuation joins tokens
                i += 2
                continue
            buf += [c, s[i + 1]]
            esc = len(buf)                # `\ #1` keeps the `#` in its word
            i += 2
            continue
        if c in ("'", '"'):
            q = c
            buf.append(c)
            i += 1
            continue
        if c == "#" and (not buf or (buf[-1] in " \t" and len(buf) != esc)):
            while i < n and s[i] != "\n":
                i += 1
            continue
        if s.startswith("<<<", i):        # a here string: its second < is no heredoc
            buf.append("<<<")
            i += 3
            continue
        if c == "<" and s.startswith("<<", i):
            m = HEREDOC.match(s, i)
            if m:
                pending.append((m.group(1) == "-", heredoc_word(m.group(2)),
                                any(ch in m.group(2) for ch in "'\"\\"), docs))
                buf.append(m.group(0))
                i = m.end()
                continue
        if c == "`" or s.startswith("$(", i):
            bodies, i = substitution(s, i)  # bodies run first; outer sees a token
            segs += [x for b in bodies for x in (OPEN, *segments(b), CLOSE)]
            buf.append(SUBST)
            continue
        if (c == "&" and (s.startswith("&>", i) or (buf and buf[-1] in "<>"))) \
                or (c == "|" and buf and buf[-1] == ">"):
            buf.append(c)                 # a redirection, not a separator
            i += 1
            continue
        if cases and c in " \t\n;&|)" and "".join(buf).strip() == "esac":
            cases.pop()                   # `esac` closes the innermost case
        if cases and cases[-1] == "pattern":
            if c == "(":                  # an extglob group, or the optional `(`
                if pdepth or "".join(buf).strip():
                    pdepth += 1
                    buf.append(c)
            elif c == ")" and pdepth:
                pdepth -= 1
                buf.append(c)
            elif c == ")":                # the pattern ends: the arm body follows
                buf, cases[-1] = [], "body"
            elif c == "\n":
                buf.append(" ")
                i = read_docs(i + 1)
                continue
            else:
                buf.append(c)
            i += 1
            continue
        if cases and c == ";" and s.startswith((";;", ";&"), i):
            emit(SEP)                     # the arm ends; another pattern may follow
            segs.append(ARM_END if s.startswith(";;", i) and
                        not s.startswith(";;&", i) else ARM_FALL)
            i += 3 if s.startswith(";;&", i) else 2
            cases[-1], pdepth = "pattern", 0
            continue
        if c in " \t\n" and CASE_HEAD.fullmatch("".join(buf)):
            emit(SEP)                     # `case WORD in`: patterns follow
            cases.append("pattern")
            pdepth = 0
            i = read_docs(i + 1) if c == "\n" else i + 1
            continue
        if c in ";&|()\n":
            seg = Seg("".join(buf))
            seg.docs = docs
            segs.append(seg)
            buf, docs = [], []
            if c in "()":
                segs.append(OPEN if c == "(" else CLOSE)
            elif c in "&|" and s.startswith(c * 2, i):
                segs.append(AND if c == "&" else OR)
                i += 1
            elif c == "|":
                segs.append(PIPE)
                if s.startswith("|&", i):
                    i += 1                # |& is a pipe too
            else:
                segs.append(BG if c == "&" else SEP)
            i += 1
            if c == "\n":
                i = read_docs(i)
            continue
        buf.append(c)
        i += 1
    seg = Seg("".join(buf))
    seg.docs = docs
    segs.append(seg)
    return segs


def expand(word, env):
    """Expand ~ and $VAR in a path word; raise Unresolved for unknown vars."""
    if XARGS in word:
        raise Unresolved("xargs fills it in from its input")
    if word == "~" or word.startswith("~/"):
        home = env.get("HOME", os.path.expanduser("~"))
        if home == UNCERTAIN:
            raise Unresolved("$HOME may or may not have been changed")
        word = home + word[1:]

    def sub(m):
        name = m.group(1) or m.group(2)
        if name not in env:
            raise Unresolved(f"${name} is not set in this command")
        if env[name] == UNCERTAIN:
            raise Unresolved(f"${name} is set by a step that may not have run")
        return env[name]

    if "`" in word or "$(" in word:
        raise Unresolved(f"{word!r} is a command substitution")
    if "$" in VAR.sub("", word):
        raise Unresolved(f"{word!r} has an expansion that is not tracked")
    return VAR.sub(sub, word)


def expand_word(word, env):
    """The words a command or subcommand word becomes once its tracked $VARs
    expand (split on whitespace, the way an unquoted expansion is; an empty
    one vanishes). Raises Unresolved when it cannot be expanded."""
    if "$" not in word and "`" not in word and XARGS not in word:
        return [word]
    return expand(word, env).split()


def path_word(word, env):
    """A path word once expanded. Quote removal hides whether a glob or brace
    in it expands (`git -C main.w*` reaches git as `main.wt`), so one that may
    is Unresolved rather than probed literally."""
    if isinstance(word, Lit):
        raise Unresolved(f"{word!r} holds a quoted `$` that quote removal hides")
    path = expand(word, env)
    if GLOB.search(path):
        raise Unresolved(f"{word!r} may expand to another path (glob or brace)")
    return path


def resolve(path, cwd, env, physical=False):
    """Absolute form of a path word relative to `cwd`. `cd` is logical (`..`
    drops the last component, as bash's default `cd -L` does); a chdir(2)
    (git -C, env -C, sudo -D, cd -P) is `physical`: symlinks are followed
    before `..`, so `link/..` lands where the link points."""
    path = path_word(path, env)
    if not os.path.isabs(path):
        if cwd is None:
            raise Unresolved("the working directory is unknown at this point")
        path = os.path.join(cwd, path)
    return os.path.realpath(path) if physical else os.path.normpath(path)


def cd_target(arg, cwd, env, physical, cdpath):
    """Where `cd <arg>` lands: a relative word not starting with `.` / `..`
    is looked up along `cdpath` (the cd's own $CDPATH, a `CDPATH=` prefix
    included) first (an empty entry is the cwd), as bash does, then taken
    relative to the cwd. `env` expands the word, as the shell does before
    a prefix assignment applies."""
    path = expand(arg, env)
    if os.path.isabs(path) or not cdpath or \
            path.split("/", 1)[0] in (".", ".."):
        return resolve(arg, cwd, env, physical)
    if cdpath == UNCERTAIN:
        raise Unresolved("$CDPATH is set by a step that may not have run")
    for entry in cdpath.split(":"):
        cand = resolve(os.path.join(entry or ".", path), cwd, env, physical)
        if os.path.isdir(cand):
            return cand
    return resolve(arg, cwd, env, physical)


def git(args, git_env):
    """The finished `git <args>`, or None when git could not run or timed out
    (each probe gets at most 5s, and never more than the hook budget left)."""
    left = min(5, DEADLINE - time.monotonic())
    if left <= 0 or GIT is None:
        return None
    try:
        return subprocess.run([GIT, *args], capture_output=True, text=True,
                              timeout=left, env={**git_env, "LC_ALL": "C",
                                              "LANGUAGE": "C"})
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None                       # ValueError: a NUL byte in an argument


def shared_reason(target, git_dir, work_tree, git_env):
    """Why a stash at `target` would touch a shared stack, else None."""
    base = ["-C", target] + ([f"--git-dir={git_dir}"] if git_dir else []) + \
        ([f"--work-tree={work_tree}"] if work_tree else [])
    r = git(base + ["rev-parse", "--path-format=absolute",
                    "--git-dir", "--git-common-dir", "--show-toplevel"], git_env)
    if r is not None and r.returncode and NOT_A_REPO.search(r.stderr):
        return None                       # not a repo: the stash fails on its own
    lines = r.stdout.splitlines() if r is not None and not r.returncode else []
    if len(lines) < 2:
        return (f"could not probe {target} (git rev-parse failed or timed "
                f"out), and an unresolvable mutating stash is denied by default")
    own, common = lines[0], lines[1]
    top = lines[2] if len(lines) > 2 else target
    if own != common:
        return f"{top} is a linked worktree"
    listing = git(base + ["worktree", "list", "--porcelain"], git_env)
    if listing is None or listing.returncode:
        return (f"could not list the worktrees of {top} (git worktree list "
                f"failed), and an unresolvable mutating stash is denied by default")
    live = [b for b in listing.stdout.split("\n\n")
            if b.startswith("worktree ") and "\nprunable" not in b]
    if len(live) > 1:
        return (f"{top} is the main checkout with {len(live) - 1} other "
                f"worktree(s) attached")
    if WORKTREE_ADDED:
        return (f"a `git worktree add` earlier in this command may attach "
                f"another worktree to {top} before the stash runs")
    return None


ENV_S_ESCAPES = {"f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
                 "#": "#", "$": "$", '"': '"', "'": "'", "\\": "\\"}


def split_string(val):
    """The words `env -S` / `--split-string` splits its operand into, by GNU
    env's rules: `\\_` separates words outside double quotes (a space inside
    them), `\\c` ends the string, `#` at a word start begins a comment, and
    `${VAR}` stays in the word for the caller to expand. A string env would
    reject (an unknown escape, an unclosed quote) runs nothing; it is split
    on whitespace so a stash in it is still judged."""
    out, cur, i, n, q = [], None, 0, len(val), None
    while i < n:
        c = val[i]
        if q == "'":
            if c == "'":
                q = None
            elif c == "\\" and val[i + 1:i + 2] in ("\\", "'"):
                cur += val[i + 1]
                i += 1
            else:
                cur += c
        elif c == "\\":
            e = val[i + 1:i + 2]
            if e == "c":
                break
            if e == "_":
                if q:
                    cur += " "
                elif cur is not None:
                    out.append(cur)
                    cur = None
            elif e in ENV_S_ESCAPES:
                cur = (cur or "") + ENV_S_ESCAPES[e]
            else:
                return val.split()
            i += 1
        elif q == '"':
            if c == '"':
                q = None
            else:
                cur += c
        elif c in " \t\n\r\f\v":
            if cur is not None:
                out.append(cur)
                cur = None
        elif c == "#" and cur is None:
            break
        elif c in ("'", '"'):
            q, cur = c, cur or ""
        else:
            cur = (cur or "") + c
        i += 1
    if q:
        return val.split()
    if cur is not None:
        out.append(cur)
    return out


def env_s_words(val, env, scoped):
    """The words `env -S val` runs: split_string()'s, each `${VAR}` replaced
    by the value env itself holds (its environment so far), before env parses
    them as its own options (`D=-C env -S '${D} /wt git stash'`). A word that
    expands to nothing is dropped. Raises Unresolved for a var it cannot know."""
    out = split_string(val)
    if not any(ENV_S_VAR.search(w) for w in out):
        return out
    seen = exported_env(env, scoped)

    def sub(m):
        v = seen.get(m.group(1), "")
        if v == UNCERTAIN:
            raise Unresolved(f"env -S reads ${{{m.group(1)}}}, which may not be set")
        return v
    return [x for x in (ENV_S_VAR.sub(sub, w) for w in out) if x]


def strip_prefix(toks, env):
    """Drop shell keywords, wrappers and VAR=val assignments before the
    command word. Returns (remaining tokens, scoped assignments, the
    `env -C` / `--chdir` directory words in order, the lookup mode: SHELL,
    NOFUNC after `command` / `builtin`, EXTERNAL after a program launcher).
    A scoped value of None means `env -u` / `env -i` removed that variable."""
    scoped, chdirs, lookup = {}, [], SHELL

    def env_opt(opt, val):
        if opt == "u":
            scoped[val] = None
        elif opt == "C":
            chdirs.append(val)
        else:                             # -i: nothing inherited survives
            scoped.clear()
            scoped.update(dict.fromkeys((*env, *GIT_TARGET)))

    while toks:
        t = toks[0]
        if t in PREFIX_WORDS:
            toks = toks[1:]
        elif os.path.basename(t) in WRAPPERS:
            wrapper, toks = os.path.basename(t), toks[1:]
            takes, long_takes, positional = WRAPPERS[wrapper]
            lookup = max(lookup, SHELL if wrapper == "time" else NOFUNC
                         if wrapper in ("command", "builtin") else EXTERNAL)
            query = repl = None           # `command -v` / `-V`; xargs's -I string
            while toks and toks[0].startswith("-") and toks[0] != "-":
                o, toks = toks[0], toks[1:]
                if o == "--":
                    break
                if o.startswith("--"):
                    name, eq, val = o.partition("=")
                    if name in long_takes:
                        if not eq:
                            val, toks = (toks[0], toks[1:]) if toks else ("", toks)
                        if name == "--chdir":
                            chdirs.append(val)
                    elif wrapper == "xargs" and name == "--replace":
                        repl = val if eq else "{}"
                    continue
                if wrapper == "command" and set(o[1:]) & set("vV"):
                    query = True
                for k in range(1, len(o)):        # a short cluster like -Eu X
                    if wrapper == "xargs" and o[k] == "i":
                        repl = o[k + 1:] or "{}"  # GNU -i[R]: its string is attached
                        break
                    if o[k] in takes:
                        val = o[k + 1:]
                        if not val:
                            val, toks = (toks[0], toks[1:]) if toks else ("", toks)
                        if wrapper == "sudo" and o[k] == "D":
                            chdirs.append(val)
                        if wrapper == "xargs" and o[k] in "IJ":
                            repl = val
                        break
            if query:                     # `command -v cd`: a lookup that runs nothing
                return [], scoped, chdirs, EXTERNAL
            toks = toks[positional:]      # `timeout 10 git ...`: the duration
            if wrapper == "xargs" and toks:  # its input fills in more arguments
                toks = [t.replace(repl, XARGS) for t in toks] if repl \
                    else toks + [XARGS]   # `--git-dir={}` stays a --git-dir
        elif os.path.basename(t) == "env":
            toks, lookup = toks[1:], EXTERNAL
            while toks and toks[0].startswith("-"):
                o, toks = toks[0], toks[1:]
                if o == "--":
                    break
                if o in ("-", "--ignore-environment"):
                    env_opt("i", None)
                elif o.startswith("--"):
                    name, eq, val = o.partition("=")
                    if name in ("--unset", "--chdir", "--split-string"):
                        if not eq:
                            val, toks = (toks[0], toks[1:]) if toks else ("", toks)
                        if name == "--split-string":
                            toks = env_s_words(val, env, scoped) + toks
                        else:
                            env_opt("u" if name == "--unset" else "C", val)
                    continue
                for k in range(1, len(o)):        # a short cluster like -iu X
                    if o[k] == "i":
                        env_opt("i", None)
                    elif o[k] in "uCS":
                        val = o[k + 1:]
                        if not val:
                            val, toks = (toks[0], toks[1:]) if toks else ("", toks)
                        if o[k] == "S":           # -S 'git stash': its words lead the argv
                            toks = env_s_words(val, env, scoped) + toks
                        else:
                            env_opt(o[k], val)
                        break
        elif ASSIGN.match(t):
            k, v = t.split("=", 1)
            scoped[k] = v
            toks = toks[1:]
        else:
            break
    return toks, scoped, chdirs, lookup


def with_scoped(env, scoped):
    """`env` as the command sees it once its VAR=val prefixes and env(1)
    unsets apply. Raises Unresolved when a GIT_* target var cannot expand."""
    out = dict(env)
    for k, v in scoped.items():
        if v is None:
            out.pop(k, None)
            continue
        try:
            out[k] = expand(v, env)
        except Unresolved:
            if k in GIT_TARGET:
                raise
            out[k] = UNCERTAIN
    return out


def exported_env(env, scoped):
    """The environment a child process (git, a child shell) inherits: what
    with_scoped() gives, minus the vars that were set but never exported.
    A command-scoped VAR=val always reaches the child; a var whose export may
    not have run is UNCERTAIN."""
    out = {k: v for k, v in with_scoped(env, scoped).items()
           if not k.startswith((FUNC, EXPORT))}
    for k in [k for k in out if k.startswith(LOCAL)]:
        name, flag = k[len(LOCAL):], out.pop(k)
        if name in scoped or name not in out:
            continue
        if flag == UNCERTAIN:
            out[name] = UNCERTAIN
        else:
            out.pop(name)
    return out


def substitute(body, env):
    """`body` with its tracked $VAR / ${VAR} expansions applied, the way the
    caller's shell expands a double-quoted eval / -c body before running it."""
    def sub(m):
        v = env.get(m.group(1) or m.group(2), UNCERTAIN)
        return m.group(0) if v == UNCERTAIN else v
    return VAR.sub(sub, body)


def variants(body, env):
    """The scripts `body` may be once the shell runs it. Quote removal hides
    whether the caller expanded its $VARs first (double quotes) or the body
    expands them itself, after its own assignments (single quotes), so both
    readings are judged."""
    pre = substitute(body, env)
    return [pre] if pre == body else [pre, body]


def merge(cwd, env, cwd2, env2):
    """State after a step that may or may not have taken effect: a cwd the
    two disagree on is unknown (None), an env var they disagree on UNCERTAIN."""
    out = dict(env)
    for k in set(env) | set(env2):
        if k.startswith(FUNC):            # either body may be the one defined,
            a = env.get(k, (None,))       # and a side without one may have none
            out[k] = a + tuple(b for b in env2.get(k, (None,)) if b not in a)
        elif env.get(k) != env2.get(k):
            out[k] = UNCERTAIN
    return (cwd if cwd == cwd2 else None), out


def shell_c_body(args):
    """(command string, the words after it, whether stdin is the script) of
    `sh [options] -c string ...`; without -c the string is None, and stdin is
    the script under `-s` (its operands then fill `$1` ...) or when no
    script-file operand follows the options. Every option is parsed first
    (`-o` / `-O` / `+o` / `+O` take a value, `--rcfile` / `--init-file` too,
    `--` / `-` end them), so the string is the first word after the options
    wherever -c sits among them."""
    has_c = has_s = False
    i = 0
    while i < len(args):
        t = args[i]
        if t in ("--", "-"):
            i += 1
            break
        if t in ("--rcfile", "--init-file"):
            i += 2
            continue
        if t.startswith("--"):
            i += 1
            continue
        if len(t) < 2 or t[0] not in "-+":
            break
        i += 1
        if t[0] == "-" and SHELL_C.fullmatch(t):
            has_c = True
        has_s = has_s or (t[0] == "-" and "s" in t)
        if t[-1] in "oO":                 # -o pipefail / -euo pipefail
            i += 1
    if has_c and i < len(args):
        return args[i], args[i + 1:], False
    if not has_c and has_s:               # `bash -s a b <<EOF`: a b are $1 $2
        return None, args[i:], True
    return None, [], not has_c and i >= len(args)


def forward(body, args):
    """`body` with the positional parameters `sh -c body $0 $1 ...` gives it
    expanded: `"$@"` as one quoted word per argument after $0, `$@` / `$*`
    as those words joined, `$N` / `${N}` as the Nth word ($0 the first)."""
    def sub(m):
        if m.group(0).startswith('"'):
            return " ".join(shlex.quote(a) for a in args[1:])
        k = m.group(1) or m.group(2)
        if k in "@*":
            return " ".join(args[1:])
        if int(k) < len(args):
            return args[int(k)]
        return XARGS if args[-1:] == [XARGS] else ""  # xargs may supply it
    return POSITIONAL.sub(sub, body)


def may_stash(text):
    """Whether `text` could spell `stash` once quotes are removed."""
    return "stash" in re.sub(r"[\"'\\$\n]", "", text)


def child_pwd(env, cwd):
    """The $PWD a child shell started in `cwd` sees: the inherited one when it
    names that directory (bash, dash and zsh keep it), else `cwd` itself."""
    if cwd is None:
        return UNCERTAIN
    pwd = env.get("PWD")
    if pwd and pwd != UNCERTAIN and os.path.realpath(pwd) == os.path.realpath(cwd):
        return pwd
    return cwd


def judge(cmd, cwd, env, depth=0):
    """Return a deny reason for the first mutating shared-stack stash in
    `cmd`, or None."""
    return scan(cmd, cwd, env, depth)[0]


def scan(cmd, cwd, env, depth, rets=None):
    """(deny reason or None, cwd, env) after `cmd`. Tracks cd and plain
    assignments across segments; a subshell's are undone when it closes.
    The state at each `return` is appended to `rets` (see run_here).
    A step in an and-or list may not have run, so once the list ends (or an
    `||` follows it) a cwd it changed is unknown and an env var it changed
    UNCERTAIN. Pipeline elements before the last and a backgrounded list run
    in subshells; the last element does in bash but not zsh, so its changes
    are uncertain too."""
    scopes, blocks = [], []               # blocks: state where each if/loop/case began
    lst = (cwd, dict(env))                # state where this and-or list began
    elem = lst                            # ... and this pipeline element
    cond, piped = None, False             # cond: (AND, state if the list so far
                                          # failed) / (OR, state if it succeeded)
    func, fdepth, skip = None, 0, 0       # state at a `f() {` definition, its { } depth
    fname, fbody = None, []               # the function being defined, its segments
    rets = [] if rets is None else rets
    segs = (list(cmd) if isinstance(cmd, list) else segments(cmd)) + [SEP]
    for idx, seg in enumerate(segs):
        if skip:
            skip -= 1
            continue
        if func is not None:
            fbody.append(seg)
        nxt = segs[idx + 1:idx + 4]
        if type(seg) is Seg and FUNC_DEF.fullmatch(seg) and len(nxt) == 3 and \
                nxt[0] == OPEN and type(nxt[1]) is Seg and not nxt[1].strip() \
                and nxt[2] == CLOSE:      # `f()` / `function f ()`: a definition
            skip = 3                      # (an empty `( )` is not a valid subshell)
            body = next((s for s in segs[idx + 4:]
                         if s != SEP and (type(s) is not Seg or s.strip())), None)
            if func is None and type(body) is Seg and body.split()[:1] == ["{"]:
                func = (cwd, dict(env), lst, elem, cond, piped, blocks)
                blocks, fname, fbody = [], seg.split()[-1], []
            continue
        if seg == OPEN:
            scopes.append((cwd, dict(env), lst, elem, cond, piped, blocks))
            lst = elem = (cwd, dict(env))
            cond, piped = None, False
            blocks = []
            continue
        if seg == CLOSE:
            if scopes:
                cwd, env, lst, elem, cond, piped, blocks = scopes.pop()
            continue
        if seg == PIPE:                   # the left side ran in a subshell
            cwd, env, piped = elem[0], dict(elem[1]), True
            continue
        if seg in (AND, OR, SEP, BG):
            if piped:
                cwd, env = merge(cwd, env, *elem)
                piped = False
            if seg == BG:                 # the whole list ran in the background
                cwd, env = lst[0], dict(lst[1])
            else:                         # the list so far succeeded (ok) or failed
                ok = (cwd, env)           # (bad); a failed step may have half-run
                bad = ok if seg == SEP else merge(*elem, cwd, env)
                if cond and cond[0] == AND:   # a skipped step leaves the failed state
                    bad = merge(*cond[1], *bad)
                elif cond:                # `a || b`: a may have succeeded instead
                    ok = merge(*cond[1], *ok)
                if seg == AND:            # the next step runs only on success
                    (cwd, env), cond = ok, (AND, bad)
                elif seg == OR:           # ... only on failure
                    (cwd, env), cond = bad, (OR, ok)
                else:
                    cwd, env = merge(*ok, *bad) if cond else ok
            if seg in (SEP, BG):
                lst, cond = (cwd, dict(env)), None
            elem = (cwd, dict(env))
            continue
        if seg in (ARM_END, ARM_FALL):    # a case arm ends; the next starts afresh
            if blocks and blocks[-1][3] == "case":
                b = blocks[-1]            # (or, after `;&` / `;;&`, may fall through)
                b[4] = (cwd, dict(env)) if b[4] is None else merge(*b[4], cwd, env)
                cwd, env = (b[0], dict(b[1])) if seg == ARM_END else \
                    merge(cwd, env, b[0], b[1])
                lst = elem = (cwd, dict(env))
            continue
        for doc, quoted in seg.docs:      # an unquoted heredoc runs its $(...)
            for body in [] if quoted else expansions(doc):
                reason = judge(body, cwd, dict(env), depth)
                if reason:
                    return reason, cwd, env
        try:
            toks, herestrs, redirs = words(seg)
        except ValueError:
            toks, herestrs, redirs = seg.split(), [], [("<", "?")]
        if func is None and toks[:1] == ["function"] and toks[2:3] == ["{"]:
            func = (cwd, dict(env), lst, elem, cond, piped, blocks)
            fname, blocks, toks = toks[1], [], toks[2:]  # `function f {`: the body follows
            fbody = [Seg(re.sub(r"^\s*function\s+\S+", "", seg))]
            fbody[0].docs = seg.docs
        while toks and toks[0] in BLOCK_WORDS:
            w, toks = toks[0], toks[1:]
            if func is not None and w in ("{", "}"):
                fdepth += 1 if w == "{" else -1
                if fdepth == 0:           # the body ends: it runs only where f is called
                    cwd, env, lst, elem, cond, piped, blocks = func
                    env[FUNC + fname] = ((tuple(fbody), " ".join(
                        [*fbody, *(d for b in fbody for d, _ in getattr(b, "docs", ()))])),)
                    func = None
                continue
            if w in OPENERS:              # a branch or loop body may be skipped
                blocks.append([cwd, dict(env), w in LOOPS and loop_start(segs, idx),
                               w, None])  # ..., opener, merged ends of case arms
                if w == "case":           # `case WORD in` runs no command
                    toks = []
            if w in ("for", "select") and toks and ASSIGN.match(toks[0] + "="):
                bind_loop_var(toks, env, w == "for")
                toks = []                 # the body follows in later segments
            elif w in ("else", "elif") and blocks:
                cwd, env = merge(cwd, env, *blocks[-1][:2])
            elif w in CLOSERS and blocks:
                c0, e0, start, _, arms = blocks.pop()
                cwd, env = merge(cwd, env, c0, e0)
                if arms:                  # any arm that ran may be the one that ended it
                    cwd, env = merge(cwd, env, *arms)
                if start is not False and (cwd, env) != (c0, e0):
                    reason, cwd, env = later_passes(segs[start:idx], cwd, env,
                                                    depth, rets)
                    if reason:
                        return reason, cwd, env
        try:
            toks, scoped, chdirs, lookup = strip_prefix(toks, env)
        except Unresolved as e:           # `env -S '${X} ...'` with $X unknown
            if may_stash(seg):
                return blocked("a command that may run `git stash`", e), cwd, env
            continue
        opaque = None
        if toks and ("$" in toks[0] or "`" in toks[0] or XARGS in toks[0]):
            try:                          # `"$B" stash pop` runs what $B holds
                toks = expand_word(toks[0], env) + toks[1:]
            except Unresolved as e:
                opaque = str(e)
            else:
                try:
                    toks, more, dirs, how = strip_prefix(toks, env)
                except Unresolved as e:
                    if may_stash(seg):
                        return blocked("a command that may run `git stash`", e), cwd, env
                    continue
                scoped.update(more)
                chdirs += dirs
                lookup = max(lookup, how)
        if lookup == EXTERNAL and toks[:1] and toks[0] in STATE_BUILTINS:
            continue                      # `env cd x`: a child process, not this shell
        if lookup == EXTERNAL and not toks:
            continue                      # `env A=b`: prints the env, sets nothing
        if not toks:
            for k, v in scoped.items():   # bare `A=b` sets shell state
                if v is None:
                    continue
                if k not in env:          # a new var stays unexported, unless
                    flag = env.pop(EXPORT + k, None)  # `export k` ran while unset
                    if flag != "1":
                        env[LOCAL + k] = UNCERTAIN if flag == UNCERTAIN else "1"
                try:
                    env[k] = expand(v, env)
                except Unresolved:
                    env[k] = UNCERTAIN
            continue
        head = toks[0]
        if lookup == SHELL and FUNC + head in env:  # a call: the body runs here
            bodies = env[FUNC + head]
            defs = [b for b in bodies if b is not None]
            args = ["$0", *(substitute(a, env) for a in toks[1:])]
            scripts, texts = [], []
            for b, t in defs:             # `f() { "$@"; }; f git stash`: its args fill $@
                fwd = [forward_seg(x, args) for x in b]
                same = all(x == y and getattr(x, "docs", ()) == getattr(y, "docs", ())
                           for x, y in zip(fwd, b))
                scripts += [fwd] if same else [fwd, list(b)]
                texts += [t, forward(t, args)]
            reason, c, e = run_here(scripts, texts, cwd, env, scoped, depth)
            if reason:
                return reason, cwd, env
            if None in bodies:            # its definition may have been skipped:
                rest = {k: v for k, v in env.items() if k != FUNC + head}
                reason, c2, e2 = scan([seg], cwd, rest, depth)  # then it is a command
                if reason:
                    return reason, cwd, env
                e2.setdefault(FUNC + head, bodies)
                c, e = merge(c, e, c2, e2)
            cwd, env = c, e
            continue
        if head == "return":              # the function's state may end here
            rets.append((cwd, dict(env)))
            continue
        if head in ("export", "unset"):
            opts = "".join(t[1:] for t in toks[1:] if t.startswith("-"))
            for t in toks[1:]:
                k, eq, v = t.partition("=")
                if t.startswith("-") or not ASSIGN.match(k + "="):
                    continue
                if head == "unset":
                    if "f" in opts:
                        env.pop(FUNC + k, None)
                    else:
                        env.pop(k, None)
                        env.pop(LOCAL + k, None)
                        env.pop(EXPORT + k, None)
                    continue
                if eq:
                    try:
                        env[k] = expand(v, env)
                    except Unresolved:
                        env[k] = UNCERTAIN
                if "n" in opts:           # export -n: set, but no longer exported
                    env[LOCAL + k] = "1"
                    env.pop(EXPORT + k, None)
                else:
                    env.pop(LOCAL + k, None)
                    if k not in env:      # the export outlives the unset value
                        env[EXPORT + k] = "1"
            continue
        if head in ("cd", "pushd", "popd"):
            if head == "pushd" and any(re.fullmatch(r"-[A-Za-z]*n[A-Za-z]*", a)
                                       for a in toks[1:]):
                continue                  # pushd -n: only the dir stack changes
            args = [a for a in toks[1:] if a == "-" or not a.startswith("-")]
            physical = any(a.startswith("-") and "P" in a for a in toks[1:]
                           if a not in args)
            old, old_env = cwd, dict(env)
            try:
                if head == "popd" or args[:1] == ["-"] or \
                        (head == "pushd" and not args):  # swap / rotate (-N)
                    raise Unresolved("cd -/popd target is not tracked")
                own = with_scoped(env, scoped)  # `CDPATH=x cd y` / `HOME=x cd`
                cwd = (cd_target(args[0], cwd, env, physical, own.get("CDPATH", ""))
                       if args else own.get("HOME"))
                if cwd == UNCERTAIN:
                    cwd = None
            except Unresolved:
                cwd = None
            if cwd is not None and not (os.path.isdir(cwd) and os.access(cwd, os.X_OK)):
                cwd = None                # the cd fails; where the shell stays is untracked
            if cwd is None:
                env["PWD"] = env["OLDPWD"] = UNCERTAIN
            else:                         # bash keeps $PWD / $OLDPWD in step
                env["PWD"], env["OLDPWD"] = cwd, (UNCERTAIN if old is None
                                                  else old)
            if any(not SAFE_REDIR.fullmatch(w) for _, w in redirs):
                cwd, env = merge(old, old_env, cwd, env)  # a failed redirection skips the cd
            continue
        run_cwd = cwd
        try:
            for d in chdirs:              # each env -C is relative to the last
                run_cwd = resolve(d, run_cwd, env, physical=True)
        except Unresolved:
            run_cwd = None
        if opaque:                        # judge it as if the word expands to git
            wrote = len(ALIAS_WRITTEN)
            if judge_git(toks[1:], run_cwd, env, scoped, depth, opaque_cmd=True):
                return ("[stash-guard] Blocked a command whose name could not "
                        f"be resolved ({opaque}): run as git, it is a mutating "
                        "stash on a shared stack, and an unresolvable mutating "
                        "stash is denied by default. " + ALTERNATIVES), cwd, env
            if len(ALIAS_WRITTEN) > wrote:
                env[ALIAS_WRITE] = "1"    # a loop's next pass must see it
            continue
        name = os.path.basename(head)
        if name in SHELLS or name == "eval":
            if name == "eval":
                raw, pos = " ".join(toks[1:]), []
            else:                         # -c, or a cluster like -lc / -ec
                raw, pos, from_stdin = shell_c_body(toks[1:])
            if raw:
                scripts = variants(raw, env)  # `eval "$CMD"` runs what $CMD holds
                if pos:                   # `bash -c '"$@"' _ git stash`: the body runs its args
                    args = [substitute(a, env) for a in pos]
                    scripts = list(dict.fromkeys([forward(b, args)
                                                  for b in scripts] + scripts))
            elif name == "eval" or not from_stdin:
                continue                  # `bash script.sh <<< x`: x is the script's data
            else:                         # `bash <<EOF` / `bash <<< ...`: stdin is the script
                scripts = [s for doc, quoted in seg.docs
                           for s in ([doc] if quoted else variants(doc, env))]
                scripts += [s for h in herestrs for s in variants(h, env)]
                if pos:                   # `bash -s git stash <<EOF`: they fill $1 ...
                    args = [name, *(substitute(a, env) for a in pos)]
                    scripts = list(dict.fromkeys([forward(b, args)
                                                  for b in scripts] + scripts))
            if not scripts:
                continue
            if name == "eval" and lookup != EXTERNAL:  # eval shares this shell
                reason, cwd, env = run_here(scripts, scripts, cwd, env, scoped,
                                            depth, rets)
                if reason:
                    return reason, cwd, env
                continue
            if depth >= MAX_DEPTH:
                reason = nested_bar(scripts, depth)
                if reason:
                    return reason, cwd, env
                continue
            try:                          # a child shell gets the exports
                body_env = exported_env(env, scoped)
            except Unresolved as e:
                reason = body_unresolved(scripts, e)
                if reason:
                    return reason, cwd, env
                continue
            body_env["PWD"] = child_pwd(body_env, run_cwd)
            for s in scripts:             # a child shell: its state is its own
                reason = judge(s, run_cwd, dict(body_env), depth + 1)
                if reason:
                    return reason, cwd, env
            continue
        if name != "git":
            continue
        wrote = len(ALIAS_WRITTEN)
        reason = judge_git(toks[1:], run_cwd, env, scoped, depth)
        if reason:
            return reason, cwd, env
        if len(ALIAS_WRITTEN) > wrote:
            env[ALIAS_WRITE] = "1"        # a loop's next pass must see it
    if scopes:                            # an unclosed ( ends with the command
        cwd, env = scopes[0][:2]
    return None, cwd, env


def bind_loop_var(toks, env, known):
    """Set a `for` / `select` loop's variable (`toks` = NAME [in WORD...]) the
    way its body sees it: the one value a `for` over a single resolvable word
    takes, else UNCERTAIN (several values, `"$@"`, a glob, a user's pick)."""
    name, val = toks[0], UNCERTAIN
    if known and toks[1:2] == ["in"] and len(toks) == 3 and not GLOB.search(toks[2]):
        try:
            vals = expand_word(toks[2], env)
            val = vals[0] if len(vals) == 1 else UNCERTAIN
        except Unresolved:
            pass
    if name not in env:                   # like a bare assignment: unexported
        flag = env.pop(EXPORT + name, None)
        if flag != "1":
            env[LOCAL + name] = UNCERTAIN if flag == UNCERTAIN else "1"
    env[name] = val


def loop_start(segs, idx):
    """Index where the text a loop repeats begins: the segment holding its
    opener word, plus any `$(...)` in that segment, which segments() emits
    just before it (a `while $(cmd)` condition reruns every pass)."""
    while idx and segs[idx - 1] == CLOSE:
        depth, idx = 0, idx - 1
        while idx >= 0:
            depth += {CLOSE: 1, OPEN: -1}.get(segs[idx], 0)
            if depth == 0:
                break
            idx -= 1
    return max(idx, 0)


def later_passes(body, cwd, env, depth, rets):
    """(deny reason or None, cwd, env) for a loop's second and later passes.
    `cwd` / `env` merge its start and the end of its first pass; each pass
    rescans the condition and body from that merged state until it stops
    changing, so a cd or export a pass makes is uncertain in the next one
    (`for i in 1 2; do git stash clear; cd /shared; done`)."""
    for _ in range(LOOP_PASSES):
        reason, c, e = scan(body, cwd, dict(env), depth, rets)
        if reason:
            return reason, cwd, env
        c, e = merge(cwd, env, c, e)
        if (c, e) == (cwd, env):
            return None, cwd, env
        cwd, env = c, e
    cwd, env = invalidated(env)           # never settled: trust nothing it touched
    return scan(body, cwd, dict(env), depth, rets)[0], cwd, env


def forward_seg(seg, args):
    """A function body segment with the call's positional parameters
    expanded (see forward()), its unquoted heredocs too; markers pass."""
    if type(seg) is not Seg:
        return seg
    out = Seg(forward(seg, args))
    out.docs = [(d if q else forward(d, args), q) for d, q in seg.docs]
    return out


def nested_bar(texts, depth):
    """The deny reason when bodies past the scan depth may run a stash."""
    if depth >= MAX_DEPTH and any(may_stash(t) for t in texts):
        return ("[stash-guard] Blocked a shell body that may run `git stash`: "
                "it is nested too deeply to inspect, and an uninspected "
                "mutating stash is denied by default. " + ALTERNATIVES)
    return None


def body_unresolved(texts, e):
    """The deny reason when a body that may stash gets an unresolvable env."""
    if not any(may_stash(t) for t in texts):
        return None
    return ("[stash-guard] Blocked a shell body that may run `git stash`: "
            f"could not resolve which repo it targets ({e}), and an "
            "unresolvable mutating stash is denied by default. " + ALTERNATIVES)


def invalidated(env):
    """(cwd, env) after a body that runs in this shell went uninspected: any
    cwd, var or export it touched is unknown, git's target vars included."""
    out = {k: (v if k.startswith(FUNC) else UNCERTAIN) for k, v in env.items()}
    out.update(dict.fromkeys(GIT_TARGET + CONFIG_HOME, UNCERTAIN))
    return None, out


def run_here(scripts, texts, cwd, env, scoped, depth, rets=None):
    """(deny reason or None, cwd, env) after bodies run in this shell (an
    `eval`, a function call): each alternative is scanned in the caller's
    state, readings that disagree leave it uncertain, its cd / exports stay,
    and a command-scoped `A=b` is exported for the call and lasts only for
    it. `texts` are the bodies as text, for the depth bar. A `return` in an
    eval leaves the function that runs it, so an eval passes its caller's
    `rets`; a function call (`rets` None) collects its own, and its state
    afterwards is uncertain wherever a `return` state and its end disagree."""
    if depth >= MAX_DEPTH:
        reason = nested_bar(texts, depth)
        return (reason, cwd, env) if reason else (None, *invalidated(env))
    try:
        body_env = with_scoped(env, scoped)
    except Unresolved as e:
        reason = body_unresolved(texts, e)
        return (reason, cwd, env) if reason else (None, *invalidated(env))
    for k in scoped:
        body_env.pop(LOCAL + k, None)
    outs = []
    for s in scripts:
        own = [] if rets is None else rets
        reason, c, e = scan(s, cwd, dict(body_env), depth + 1, own)
        if reason:
            return reason, cwd, env
        if rets is None:
            for rc, renv in own:
                c, e = merge(c, e, rc, renv)
        outs.append((c, e))
    cwd, after = outs[0]
    for c, e in outs[1:]:
        cwd, after = merge(cwd, after, c, e)
    for k in scoped:
        for key in (k, LOCAL + k, EXPORT + k):
            if key in env:
                after[key] = env[key]
            else:
                after.pop(key, None)
    return None, cwd, after


def blocked(label, why):
    """The deny reason for a mutating stash whose target is unresolvable."""
    return (f"[stash-guard] Blocked {label}: could not resolve which repo it "
            f"targets ({why}), and an unresolvable mutating stash is denied "
            f"by default. " + ALTERNATIVES)


def judge_git(args, cwd, env, scoped=None, depth=0, opaque_cmd=False):
    """Deny reason for one git invocation's argv (after `git`), or None.
    `env` expands the argv (the shell expands words before a command-scoped
    VAR=val takes effect); `scoped` only reaches git's own environment.
    `--git-dir` / `--work-tree` stay as written: git resolves a relative one
    after every `-C`, and so does the probe, which gets the same options.
    `opaque_cmd`: the command word itself is unresolvable (`$PY -m pytest`),
    so when the repo is unknown and nothing on the line or in the env can
    define an alias (`-c alias.<word>` / `include.*`, an unresolvable `-c`,
    GIT_CONFIG_* vars), no alias lookup is attempted: failing closed there
    would deny every `$VAR args` after an uncertain cd."""
    scoped = scoped or {}
    target, git_dir, work_tree, configs, i = cwd, None, None, [], 0
    pending_unresolved = config_unresolved = None
    while i < len(args) and args[i].startswith("-"):
        opt = args[i]
        name, _, inline = opt.partition("=")
        value = None
        if name in GIT_OPTS_WITH_VALUE:
            if inline:
                value = Lit(inline) if isinstance(opt, Lit) else inline
                i += 1
            else:
                value = args[i + 1] if i + 1 < len(args) else ""
                i += 2
        else:
            i += 1
        try:
            if name == "-C" and value:
                target = resolve(value, target, env, physical=True)
            elif name == "--git-dir" and value:
                git_dir = path_word(value, env)
            elif name == "--work-tree" and value:
                work_tree = path_word(value, env)
            elif name == "-c" and value:
                try:
                    configs.append(expand(value, env))
                except Unresolved as e:
                    config_unresolved = str(e)
            elif name == "--config-env" and value:
                if XARGS in value:
                    config_unresolved = "xargs fills it in from its input"
                else:                     # read once `seen` is known
                    configs.append(tuple(value.partition("=")[::2]))
        except Unresolved as e:
            pending_unresolved = str(e)
    if i >= len(args):
        return None
    opaque = None
    try:                                  # `git "$S" pop` runs what $S holds
        rest = expand_word(args[i], env) + args[i + 1:]
    except Unresolved as e:
        rest, opaque = ["stash"] + args[i + 1:], str(e)
    if not rest:
        return None
    if rest[0] == "config" and config_may_alias(rest[1:]):
        ALIAS_WRITTEN.append(rest)        # later alias lookups cannot trust the config
    try:
        seen = exported_env(env, scoped)
    except Unresolved as e:
        seen = e
    git_env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    if not isinstance(seen, Unresolved):
        git_env.update({k: v for k, v in seen.items()
                        if config_var(k) and v != UNCERTAIN})
        for k in CONFIG_HOME:             # where git finds its global config
            if k not in seen:
                git_env.pop(k, None)
            elif seen[k] != UNCERTAIN:
                git_env[k] = seen[k]
        git_env.update({k: seen[k] for k in DISCOVERY  # git finds the repo the same way
                        if seen.get(k) not in (None, UNCERTAIN)})
    resolved = []                         # --config-env=key=VAR takes VAR's exported value
    for c in configs:
        if isinstance(c, str):
            resolved.append(c)
            continue
        key, var = c
        val = UNCERTAIN if isinstance(seen, Unresolved) else seen.get(var)
        if val == UNCERTAIN:
            config_unresolved = config_unresolved or \
                f"--config-env reads ${var}, which cannot be resolved"
        elif val is not None:             # an unset VAR makes git fail outright
            resolved.append((key, var, val))  # its value never reaches a probe argv
    configs = resolved
    if rest[:2] == ["worktree", "add"]:
        WORKTREE_ADDED.append(True)
    if rest[0] != "stash" and ALIAS_WRITTEN and rest[0] not in GIT_BUILTINS and \
            not rest[0].startswith("-") and not is_git_command(rest[0], git_env):
        return blocked(f"`git {rest[0]}`", "a `git config` earlier in this "
                       "command may have written its alias, which may run a "
                       "stash in any repo (`!cd /other && git stash`)")
    if rest[0] != "stash":                # whose repo config may define the alias
        where = pending_unresolved or (target is None and "the working "
                                       "directory is unknown") or \
            (seen if isinstance(seen, Unresolved) else None) or \
            next((f"${k} is set by a step that may not have run"
                  for k in (*GIT_TARGET, *CONFIG_HOME, *DISCOVERY,
                            *sorted(filter(config_var, seen)))
                  if seen.get(k) == UNCERTAIN), None)
        repo_unknown = pending_unresolved or target is None or \
            (not isinstance(seen, Unresolved) and
             any(seen.get(k) == UNCERTAIN for k in GIT_TARGET))
        keys = [(c.split("=", 1)[0] if isinstance(c, str) else c[0]).lower()
                for c in configs]         # --config-env entries are (key, var, val)
        on_line = isinstance(seen, Unresolved) or config_unresolved or \
            f"alias.{rest[0].lower()}" in keys or \
            f"alias.{rest[0].lower()}.command" in keys or \
            any(k.startswith(("include.", "includeif.")) for k in keys) or \
            any(ALIAS_ENV.fullmatch(k) for k in seen)
        if opaque_cmd and repo_unknown and not on_line:
            return None                   # no repo whose config could define it
        return judge_alias(rest, target, git_dir, work_tree, configs,
                           config_unresolved, seen, git_env, depth,
                           str(where) if where else None)
    sub = rest[1] if len(rest) > 1 else "push"
    try:
        sub = (expand_word(sub, env) or ["push"])[0]
    except Unresolved as e:
        opaque = opaque or str(e)
    if sub in READ_ONLY and not opaque:
        return None
    label = f"`git stash{'' if len(rest) < 2 else ' ' + rest[1]}`"
    if opaque:
        label = f"`git {' '.join(args[i:i + 2])}`"
    if pending_unresolved or target is None:
        return blocked(label, pending_unresolved or "the working directory is unknown")
    if isinstance(seen, Unresolved):
        return blocked(label, seen)
    for k in (*GIT_TARGET, *DISCOVERY):
        if seen.get(k) == UNCERTAIN:
            return blocked(label, f"${k} is set by a step that may not have run")
        if k in seen and k in GIT_TARGET:
            git_env[k] = seen[k]
    if git_dir is None and "GIT_DIR" in git_env:
        git_dir = git_env.pop("GIT_DIR")
    reason = shared_reason(target, git_dir, work_tree, git_env)
    if not reason:
        return None
    if opaque:                            # a stash only if the word expands to one
        reason += (f", and a word of it could not be resolved ({opaque}), "
                   f"so it may be a mutating stash")
    return f"[stash-guard] Blocked {label}: {reason}. " + ALTERNATIVES


def config_may_alias(args):
    """Whether `git config <args>` may write (or drop) an alias or an include
    that defines one: a set, unset, rename / remove of an `alias` or
    `include` / `includeIf` key or section (or one it cannot read), or an
    edit. A bare `git config name` and every --get / --list form only read."""
    opts, pos, i = set(), [], 0
    while i < len(args):
        a = args[i]
        if a.startswith("-") and a != "-":
            name = a.split("=", 1)[0]
            opts.add(name)
            i += name in CONFIG_OPTS_WITH_VALUE and "=" not in a
        else:
            pos.append(a)
        i += 1
    if opts & CONFIG_READS or pos[:1] in (["get"], ["list"]):
        return False
    if opts & {"-e", "--edit"} or pos[:1] == ["edit"]:
        return True
    sub = pos[:1] in (["set"], ["unset"], ["rename-section"], ["remove-section"])
    keys = pos[1:] if sub else pos
    if not sub and len(keys) < 2 and not opts & CONFIG_WRITES:
        return False                      # `git config alias.x`: a read
    renames = pos[:1] == ["rename-section"] or "--rename-section" in opts
    return any("$" in k or "`" in k or XARGS in k or k.split(".", 1)[0].lower()
               in ("alias", "include", "includeif") for k in keys[:2 if renames else 1])


def config_var(k):
    """Whether env var `k` picks config every git command reads, so an alias
    too. GIT_CONFIG is read by `git config` alone, never by the alias run."""
    return k.startswith("GIT_CONFIG") and k != "GIT_CONFIG"


def is_git_command(name, git_env):
    """Whether `git <name>` runs a dashed command (`git-<name>` in git's
    exec path or on $PATH), which git tries before any alias."""
    if "/" in name:
        return False
    r = git(["--exec-path"], git_env)
    dirs = ([r.stdout.strip()] if r is not None and not r.returncode else []) + \
        git_env.get("PATH", "").split(os.pathsep)
    return any(d and os.access(os.path.join(d, "git-" + name), os.X_OK)
               for d in dirs)


def final_word(words_):
    """The subcommand an alias's words run, past git's own options."""
    i = 0
    while i < len(words_) and words_[i].startswith("-"):
        i += 2 if words_[i] in GIT_OPTS_WITH_VALUE else 1
    return words_[i] if i < len(words_) else None


def judge_alias(rest, target, git_dir, work_tree, configs, config_unresolved,
                seen, git_env, depth, unresolved=None):
    """Deny reason when `git <rest>` runs an alias (`-c alias.x=...` on the
    command line, or configured) that can reach a mutating stash, else None.
    git ignores an alias that shadows a builtin, so those are not looked up.
    A `!` alias is a shell body run at the repo's top level. `unresolved`
    says why the repo whose config may define it is unknown."""
    name = rest[0]
    if name in GIT_BUILTINS or name.startswith("-"):
        return None
    label = f"`git {name}`"
    if config_unresolved:
        return blocked(label, f"a `-c` value that may define its alias "
                              f"cannot be expanded: {config_unresolved}")
    if unresolved:
        if is_git_command(name, git_env):
            return None                   # a real command: no alias can shadow it
        return blocked(label, f"it may be an alias defined in that repo's "
                              f"config: {unresolved}")
    base = (["-C", target] if target else []) + \
        ([f"--git-dir={git_dir}"] if git_dir else []) + \
        ([f"--work-tree={work_tree}"] if work_tree else [])
    env = git_env if isinstance(seen, Unresolved) else {
        **git_env, **{k: seen[k] for k in GIT_TARGET
                      if k in seen and seen[k] != UNCERTAIN}}
    for n, c in enumerate(configs):       # a --config-env value goes by a name of
        if isinstance(c, str):            # ours, never on argv or under the request's
            base += ["-c", c]
        else:
            base.append(f"--config-env={c[0]}=STASH_GUARD_CONFIG_{n}")
            env = {**env, f"STASH_GUARD_CONFIG_{n}": c[2]}
    # `[alias] x = ...` (name matched case-insensitively) and `[alias "x"]
    # command = ...` (matched exactly) both define it; the last one read wins.
    r = git(base + ["config", "-z", "--get-regexp", r"^alias\."], env)
    if r is None or r.returncode not in (0, 1):
        return blocked(label, "its alias lookup (git config) failed or timed out")
    keys = {f"alias.{name}.command"} | \
        ({f"alias.{name.lower()}"} if re.fullmatch(r"[A-Za-z0-9-]+", name) else set())
    value = ""
    for entry in r.stdout.split("\0") if r.returncode == 0 else ():
        key, _, val = entry.partition("\n")
        if key in keys:
            value = val.strip()
    if not value:
        return None
    if depth >= MAX_DEPTH:                # past here only a builtin ends the chain
        if value.startswith("!"):
            ends = not may_stash(value) and "git" not in value
        else:
            try:
                w = final_word(shlex.split(value))
            except ValueError:
                w = None
            ends = w in GIT_BUILTINS and not may_stash(value)
        if not ends:
            return ("[stash-guard] Blocked " + label + ": its alias chain is "
                    "nested too deeply to inspect, and an uninspected mutating "
                    "stash is denied by default. " + ALTERNATIVES)
        return None
    # The alias acts in the repo the invocation names, so its own git sees
    # that repo: carry the options over as the env git sets for an alias.
    child = {} if isinstance(seen, Unresolved) else dict(seen)
    for k, v in (("GIT_DIR", git_dir), ("GIT_WORK_TREE", work_tree)):
        if v:
            child[k] = v if os.path.isabs(v) or not target else os.path.join(target, v)
    if value.startswith("!"):             # git hands its `-c` options on in the env
        quoted = " ".join("'" + kv.replace("'", "'\\''") + "'" for kv in (
            c if isinstance(c, str) else f"{c[0]}={c[2]}" for c in configs))
        if quoted:
            prior = child.get("GIT_CONFIG_PARAMETERS")
            child["GIT_CONFIG_PARAMETERS"] = f"{prior} {quoted}" if prior else quoted
        run_dir = target                  # git runs it from the worktree's top level
        if target:
            top = git(base + ["rev-parse", "--show-toplevel"], env)
            if top is None or (top.returncode and not NOT_A_REPO.search(top.stderr)):
                return blocked(label, "its top-level lookup (git rev-parse) "
                                      "failed or timed out")
            if not top.returncode and top.stdout.strip():
                run_dir = top.stdout.strip()
        child["PWD"] = child_pwd(child, run_dir)
        body = value[1:]                  # git runs `sh -c '<body> "$@"' <body> <args>`
        return judge(forward(f'{body} "$@"', [body, *rest[1:]]), run_dir, child,
                     depth + 1)
    try:
        words_ = shlex.split(value)
    except ValueError:
        words_ = value.split()
    opts = [w for c in configs for w in (("-c", c) if isinstance(c, str)
                                         else ("--config-env", f"{c[0]}={c[1]}"))]
    return judge_git(opts + words_ + rest[1:], target, child, {}, depth + 1)


def main():
    """Read a PreToolUse payload on stdin; print a deny decision if needed."""
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    if not isinstance(payload, dict) or payload.get("tool_name") != "Bash":
        return 0
    cmd = (payload.get("tool_input") or {}).get("command")
    if not isinstance(cmd, str):
        return 0
    cwd = payload.get("cwd") or os.getcwd()
    try:
        reason = judge(cmd, cwd, {**os.environ, "PWD": cwd})
    except (TooDeep, RecursionError) as e:
        reason = None if not may_stash(cmd) else (
            "[stash-guard] Blocked a command that may run `git stash`: it is "
            f"nested too deeply to parse ({e}), and an uninspected mutating "
            "stash is denied by default. " + ALTERNATIVES)
    if reason:
        reason = reason.replace(XARGS, "<xargs input>")
        json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                          "permissionDecision": "deny",
                                          "permissionDecisionReason": reason}},
                  sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())

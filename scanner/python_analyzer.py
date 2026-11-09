"""Python analyzer: AST parsing + source-to-sink taint analysis.

How it works
------------
1. The file is parsed with :mod:`ast` (so strings, comments and formatting can no
   longer fool it the way they fool regexes).
2. Each function body is executed *abstractly*: every variable maps to a
   :class:`Taint` (or nothing = clean).  Taint comes from
     * **sources**  - ``request.args``, ``input()``, ``sys.argv`` ... -> ``src=True`` (High confidence)
     * **parameters** - a function argument might be attacker-controlled -> ``params={i}`` (Medium)
3. Taint propagates through assignments, concatenation, f-strings, ``%``/``.format``,
   containers and unknown calls.  It is *removed* by
     * type conversion (``int(x)``) and context-specific **sanitizers**
       (``shlex.quote`` only neutralises command injection, ``html.escape`` only XSS ...),
     * **validation guards** (``if x not in ALLOWED: raise``, ``x.isdigit()``, ``re.fullmatch``,
       ``base not in path.parents``).
4. Dangerous **sinks** (``cursor.execute``, ``os.system``, ``open`` ...) report a finding when
   an unsanitised tainted value reaches them; the finding carries the source->sink trace.
5. **Function summaries**: if ``helper(x)`` passes ``x`` to a sink, a call
   ``helper(request.args["q"])`` is reported at the call site with the full path.
   Summaries are computed iteratively until they stop changing.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, replace
from typing import Dict, List, Optional, Set, Tuple

from . import secret_rules as sec
from .rules import make_finding

MAX_TRACE = 8
CONF_RANK = {"Low": 1, "Medium": 2, "High": 3}

SQL_HINT = re.compile(
    r"\b(?:select\b.+\bfrom|insert\s+into|update\b.+\bset|delete\s+from|drop\s+table|"
    r"union\s+select|where|order\s+by)\b",
    re.I | re.S,
)
SECURITY_NAME = re.compile(
    r"(?:token|passw|secret|salt|otp|nonce|session|api_?key|csrf|reset|verif|auth)", re.I)

REQUEST_ATTRS = {
    "args", "form", "values", "json", "data", "headers", "cookies", "files", "GET", "POST",
    "META", "COOKIES", "FILES", "body", "query_params", "path", "full_path", "url", "view_args",
    "get_json", "get_data", "arguments", "query", "body_arguments", "stream",
}
SOURCE_CALLS = {"input", "raw_input"}
SOURCE_METHODS = {"get_argument", "get_query_argument", "get_body_argument", "recv", "recvfrom"}
IGNORED_PARAMS = {"self", "cls", "request", "req"}

# methods that keep a string "tainted" when called on a tainted object
PROPAGATING_METHODS = {
    "strip", "lstrip", "rstrip", "lower", "upper", "title", "capitalize", "casefold", "format",
    "format_map", "join", "replace", "encode", "decode", "split", "rsplit", "splitlines",
    "partition", "rpartition", "get", "getlist", "items", "values", "keys", "copy", "read",
    "readline", "readlines", "center", "ljust", "rjust", "zfill", "swapcase", "translate",
    "removeprefix", "removesuffix", "pop", "setdefault", "decode_utf8", "unquote",
}

# call results that are never attacker-controlled strings
CLEAN_ALL = {
    "int", "float", "bool", "len", "hash", "id", "ord", "chr", "abs", "round", "sum",
    "isinstance", "issubclass", "type", "callable", "hasattr", "uuid.UUID", "UUID",
    "ipaddress.ip_address", "ip_address", "Decimal", "decimal.Decimal", "os.path.exists",
    "os.path.isfile", "os.path.isdir", "os.path.getsize", "url_for", "reverse", "reverse_lazy",
    "open", "io.open", "codecs.open", "range", "enumerate", "time.time", "datetime.now",
}
CLEAN_PREFIXES = ("hashlib.", "secrets.", "uuid.", "datetime.", "math.", "time.")
# sanitizers that neutralise *specific* vulnerability classes only
SAFE_FOR = {
    "html.escape": {"SC003"}, "escape": {"SC003"}, "markupsafe.escape": {"SC003"},
    "flask.escape": {"SC003"}, "cgi.escape": {"SC003"}, "bleach.clean": {"SC003"},
    "conditional_escape": {"SC003"}, "strip_tags": {"SC003"}, "force_escape": {"SC003"},
    "saxutils.escape": {"SC003"}, "xml.sax.saxutils.escape": {"SC003"},
    "shlex.quote": {"SC002"}, "pipes.quote": {"SC002"},
    "quote": {"SC002", "SC003"}, "quote_plus": {"SC002", "SC003"}, "urlencode": {"SC002", "SC003"},
    "urllib.parse.quote": {"SC002", "SC003"}, "parse.quote": {"SC002", "SC003"},
    "urllib.parse.quote_plus": {"SC002", "SC003"}, "urllib.parse.urlencode": {"SC002", "SC003"},
    "secure_filename": {"SC006"}, "werkzeug.utils.secure_filename": {"SC006"},
    "os.path.basename": {"SC006"}, "basename": {"SC006"}, "get_valid_filename": {"SC006"},
    "sanitize_filename": {"SC006"}, "slugify": {"SC001", "SC002", "SC003", "SC006"},
    "escape_string": {"SC001"}, "quote_ident": {"SC001"}, "adapt": {"SC001"},
}
VALIDATORS = {
    "isalnum", "isdigit", "isnumeric", "isalpha", "isidentifier", "isdecimal", "fullmatch",
    "match", "is_relative_to", "url_has_allowed_host_and_scheme", "is_safe_url",
    "is_safe_redirect_url", "validate", "is_valid",
}
ABORT_CALLS = {"abort", "exit", "quit", "sys.exit", "os._exit"}

SQL_METHODS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query"}
OS_COMMAND = {
    "os.system", "os.popen", "popen", "commands.getoutput", "subprocess.getoutput",
    "subprocess.getstatusoutput", "asyncio.create_subprocess_shell",
}
SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}
PATH_FUNCS_1 = {
    "open", "io.open", "codecs.open", "os.open", "os.remove", "os.unlink", "os.rmdir",
    "os.removedirs", "os.listdir", "os.scandir", "os.mkdir", "os.makedirs", "os.chmod",
    "send_file", "flask.send_file", "shutil.rmtree",
}
PATH_FUNCS_ALL = {"shutil.copy", "shutil.copyfile", "shutil.move", "shutil.copytree", "os.rename"}
PATH_METHODS = {"read_text", "read_bytes", "write_text", "write_bytes"}
HTTP_METHODS = {"get", "post", "put", "delete", "head", "patch", "options", "request"}
URL_OPEN = {"urlopen", "urllib.request.urlopen", "request.urlopen", "urllib2.urlopen", "urllib.urlopen"}
XSS_SINKS = {"Markup", "mark_safe", "HttpResponse", "make_response", "HTMLResponse"}
REDIRECTS = {"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect", "RedirectResponse"}
UNSAFE_DESER = {
    "pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "_pickle.load", "_pickle.loads",
    "marshal.load", "marshal.loads", "dill.load", "dill.loads", "jsonpickle.decode",
    "pandas.read_pickle", "pd.read_pickle",
}
SAFE_YAML_LOADERS = ("SafeLoader", "CSafeLoader", "BaseLoader")


# --------------------------------------------------------------------------------------
# taint value
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Taint:
    src: bool = False                 # derived from a definite untrusted source
    params: frozenset = frozenset()   # indexes of function parameters it derives from
    safe: frozenset = frozenset()     # rule ids this value has already been sanitised for
    sql: bool = False                 # contains SQL-looking text
    trace: tuple = ()                 # ((line, message), ...)


def merge(a: Optional[Taint], b: Optional[Taint]) -> Optional[Taint]:
    if a is None:
        return b
    if b is None:
        return a
    if a.src and not b.src:
        trace = a.trace
    elif b.src and not a.src:
        trace = b.trace
    else:
        trace = a.trace if len(a.trace) >= len(b.trace) else b.trace
    return Taint(a.src or b.src, a.params | b.params, a.safe & b.safe, a.sql or b.sql, trace)


def step(t: Optional[Taint], line: int, msg: str) -> Optional[Taint]:
    if t is None or (t.trace and t.trace[-1][1] == msg):
        return t
    trace = t.trace + ((line, msg),)
    if len(trace) > MAX_TRACE:
        trace = trace[:2] + trace[-(MAX_TRACE - 2):]
    return replace(t, trace=trace)


def dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def is_source_name(d: str) -> bool:
    if not d:
        return False
    parts = d.split(".")
    if parts[0] in ("self", "cls", "flask"):
        parts = parts[1:]
    if len(parts) >= 3 and parts[0] == "request" and parts[1] in REQUEST_ATTRS:
        return True
    if len(parts) >= 2 and parts[0] == "request" and parts[1] in REQUEST_ATTRS:
        return True
    return d in ("sys.argv", "sys.stdin") or d.startswith("sys.stdin.")


def name_key(node) -> Optional[str]:
    return dotted(node) or None


def abort_stmt(s) -> bool:
    if isinstance(s, (ast.Raise, ast.Return, ast.Continue, ast.Break)):
        return True
    if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
        return dotted(s.value.func) in ABORT_CALLS
    if isinstance(s, ast.If):
        return aborts(s.body) and bool(s.orelse) and aborts(s.orelse)
    return False


def aborts(block) -> bool:
    return bool(block) and abort_stmt(block[-1])


@dataclass
class FuncInfo:
    name: str
    params: List[str]
    sinks: Dict[int, Set[Tuple[str, int, str]]]
    ret: Optional[Taint] = None

    def sig(self):
        ret = (self.ret.src, self.ret.params, self.ret.safe) if self.ret else None
        return (tuple(sorted((k, tuple(sorted(v))) for k, v in self.sinks.items())), ret)


class Ctx:
    def __init__(self, name: str, params: List[str]):
        self.name = name
        self.params = params
        self.sinks: Dict[int, Set[Tuple[str, int, str]]] = {}
        self.ret: Optional[Taint] = None


# --------------------------------------------------------------------------------------
# analyzer
# --------------------------------------------------------------------------------------
class PythonAnalyzer:
    def __init__(self, source: str, path: str):
        self.tree = ast.parse(source)          # may raise SyntaxError - caller falls back to regex
        self.lines = source.splitlines()
        self.path = path
        self.findings: Dict[Tuple[str, int], object] = {}
        self.summaries: Dict[str, FuncInfo] = {}
        self.imports: Set[str] = set()
        self.consts: Set[str] = set()          # module-level literal collections (allowlists)
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Import):
                self.imports.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module:
                self.imports.add(n.module.split(".")[0])
        for s in self.tree.body:
            if isinstance(s, ast.Assign) and self._is_literal_collection(s.value):
                for t in s.targets:
                    if isinstance(t, ast.Name):
                        self.consts.add(t.id)

    # ---- public --------------------------------------------------------------------
    def run(self):
        funcs = [n for n in ast.walk(self.tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        counts: Dict[str, int] = {}
        for f in funcs:
            counts[f.name] = counts.get(f.name, 0) + 1
        prev = None
        for _ in range(4):                       # iterate until function summaries stabilise
            self.findings = {}
            new: Dict[str, FuncInfo] = {}
            ctx = Ctx("<module>", [])
            self.exec_block(self.tree.body, {}, ctx)
            for f in funcs:
                info = self.run_function(f)
                if counts[f.name] == 1:
                    new[f.name] = info
            self.summaries = new
            sig = {k: v.sig() for k, v in new.items()}
            if sig == prev:
                break
            prev = sig
        self.syntactic_checks()
        return list(self.findings.values())

    # ---- findings --------------------------------------------------------------------
    def add(self, rule, node, conf, detail="", trace=None, severity=None, evidence=None, line=None):
        line = line or getattr(node, "lineno", 1)
        key = (rule, line)
        old = self.findings.get(key)
        if old is not None and CONF_RANK[old.confidence] >= CONF_RANK[conf]:
            return
        text = evidence if evidence is not None else (
            self.lines[line - 1].strip() if 0 < line <= len(self.lines) else "")
        if len(text) > 220:
            text = text[:217] + "..."
        self.findings[key] = make_finding(
            rule, self.path, line, text, conf, detail=detail, trace=trace,
            end_line=getattr(node, "end_lineno", None) or line, severity=severity)

    def hit(self, rule, node, t, desc, ctx, need_sql=False):
        """Report ``rule`` if tainted value ``t`` reaches a sink described by ``desc``."""
        if t is None or rule in t.safe or not (t.src or t.params):
            return
        if need_sql and not (t.sql or t.src):
            return
        line = node.lineno
        if t.src:
            conf = "High"
            detail = f"Untrusted input reaches {desc} with no recognised sanitiser or validation."
        else:
            conf = "Medium"
            names = ", ".join(f"`{ctx.params[i]}`" for i in sorted(t.params) if i < len(ctx.params))
            detail = (f"Parameter {names} of `{ctx.name}()` reaches {desc}; "
                      f"exploitable if any caller passes untrusted data.")
            for p in t.params:
                ctx.sinks.setdefault(p, set()).add((rule, line, desc))
        self.add(rule, node, conf, detail, trace=list(t.trace) + [(line, f"reaches {desc}")])

    def weak(self, rule, node, conf, detail, severity=None):
        self.add(rule, node, conf, detail, trace=[(node.lineno, detail)], severity=severity)

    # ---- function / block execution -------------------------------------------------
    def run_function(self, fn) -> FuncInfo:
        args = fn.args
        names = [a.arg for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)]
        if names and names[0] in ("self", "cls"):
            names = names[1:]
        if args.vararg:
            names.append(args.vararg.arg)
        if args.kwarg:
            names.append(args.kwarg.arg)
        env: Dict[str, Taint] = {}
        for i, p in enumerate(names):
            if p in IGNORED_PARAMS:
                continue
            env[p] = Taint(params=frozenset({i}), trace=((fn.lineno, f"parameter `{p}` of {fn.name}()"),))
        ctx = Ctx(fn.name, names)
        self.exec_block(fn.body, env, ctx)
        return FuncInfo(fn.name, names, ctx.sinks, ctx.ret)

    def exec_block(self, stmts, env, ctx):
        for s in stmts:
            self.exec_stmt(s, env, ctx)

    def exec_stmt(self, s, env, ctx):
        m = getattr(self, "st_" + type(s).__name__, None)
        if m:
            m(s, env, ctx)
        else:                                     # unknown statement: still visit its expressions
            for c in ast.iter_child_nodes(s):
                if isinstance(c, ast.expr):
                    self.ev(c, env, ctx)

    def st_FunctionDef(self, s, env, ctx):        # analysed separately in run()
        pass

    st_AsyncFunctionDef = st_FunctionDef

    def st_ClassDef(self, s, env, ctx):
        self.exec_block(s.body, dict(env), ctx)

    def st_Assign(self, s, env, ctx):
        t = self.ev(s.value, env, ctx)
        for target in s.targets:
            self.bind(target, t, env, s.lineno)

    def st_AnnAssign(self, s, env, ctx):
        if s.value is not None:
            self.bind(s.target, self.ev(s.value, env, ctx), env, s.lineno)

    def st_AugAssign(self, s, env, ctx):
        t = merge(self.ev(s.target, env, ctx) if not isinstance(s.target, ast.Name) else env.get(s.target.id),
                  self.ev(s.value, env, ctx))
        if t is not None and isinstance(s.op, ast.Add) and self._has_sql(s.value):
            t = replace(t, sql=True)
        self.bind(s.target, t, env, s.lineno)

    def st_Expr(self, s, env, ctx):
        self.ev(s.value, env, ctx)

    def st_Return(self, s, env, ctx):
        if s.value is None:
            return
        t = self.ev(s.value, env, ctx)
        ctx.ret = merge(ctx.ret, t)
        if t is not None and self._has_html_literal(s.value):
            self.hit("SC003", s, t, "an HTML response body", ctx)

    def st_If(self, s, env, ctx):
        self.ev(s.test, env, ctx)
        clean_true, clean_false = self.guard(s.test)
        e1, e2 = dict(env), dict(env)
        for k in clean_true:
            e1.pop(k, None)
        for k in clean_false:
            e2.pop(k, None)
        self.exec_block(s.body, e1, ctx)
        self.exec_block(s.orelse, e2, ctx)
        a1, a2 = aborts(s.body), bool(s.orelse) and aborts(s.orelse)
        if a1 and not a2:
            new = e2
        elif a2 and not a1:
            new = e1
        elif a1 and a2:
            new = e1
        else:
            new = self._merge_env(e1, e2)
        env.clear()
        env.update(new)

    def st_Assert(self, s, env, ctx):
        self.ev(s.test, env, ctx)
        for k in self.guard(s.test)[0]:
            env.pop(k, None)

    def _loop(self, s, env, ctx, bind_target=None):
        before = dict(env)
        for _ in range(2):
            if bind_target is not None:
                self.bind(s.target, bind_target, env, s.lineno)
            self.exec_block(s.body, env, ctx)
        self.exec_block(s.orelse, env, ctx)
        merged = self._merge_env(before, env)
        env.clear()
        env.update(merged)

    def st_For(self, s, env, ctx):
        self._loop(s, env, ctx, self.ev(s.iter, env, ctx))

    st_AsyncFor = st_For

    def st_While(self, s, env, ctx):
        self.ev(s.test, env, ctx)
        self._loop(s, env, ctx)

    def st_With(self, s, env, ctx):
        for item in s.items:
            t = self.ev(item.context_expr, env, ctx)
            if item.optional_vars is not None:
                self.bind(item.optional_vars, t, env, s.lineno)
        self.exec_block(s.body, env, ctx)

    st_AsyncWith = st_With

    def st_Try(self, s, env, ctx):
        self.exec_block(s.body, env, ctx)
        for h in s.handlers:
            if h.name:
                env.pop(h.name, None)
            self.exec_block(h.body, env, ctx)
        self.exec_block(s.orelse, env, ctx)
        self.exec_block(s.finalbody, env, ctx)

    st_TryStar = st_Try

    def st_Match(self, s, env, ctx):
        self.ev(s.subject, env, ctx)
        envs = []
        for case in s.cases:
            e = dict(env)
            self.exec_block(case.body, e, ctx)
            envs.append(e)
        for e in envs:
            env.update(self._merge_env(env, e))

    @staticmethod
    def _merge_env(a, b):
        out = {}
        for k in set(a) | set(b):
            out[k] = merge(a.get(k), b.get(k))
        return {k: v for k, v in out.items() if v is not None}

    def bind(self, target, t, env, line):
        if isinstance(target, ast.Name):
            if t is None:
                env.pop(target.id, None)
            else:
                env[target.id] = step(t, line, f"assigned to `{target.id}`")
        elif isinstance(target, (ast.Tuple, ast.List)):
            for e in target.elts:
                self.bind(e, t, env, line)
        elif isinstance(target, ast.Starred):
            self.bind(target.value, t, env, line)
        elif isinstance(target, ast.Attribute):
            key = dotted(target)
            if key:
                if t is None:
                    env.pop(key, None)
                else:
                    env[key] = step(t, line, f"stored in `{key}`")
        elif isinstance(target, ast.Subscript):
            root = target.value
            if isinstance(root, ast.Name) and t is not None:
                env[root.id] = merge(env.get(root.id), step(t, line, f"stored in `{root.id}[...]`"))

    # ---- validation guards ----------------------------------------------------------
    def _is_literal_collection(self, node) -> bool:
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(isinstance(e, ast.Constant) for e in node.elts)
        if isinstance(node, ast.Dict):
            return all(isinstance(k, ast.Constant) for k in node.keys if k is not None)
        if isinstance(node, ast.Call) and dotted(node.func) in ("frozenset", "set", "tuple", "list") and node.args:
            return self._is_literal_collection(node.args[0])
        return False

    def guard(self, test) -> Tuple[Set[str], Set[str]]:
        """Names that become validated when ``test`` is true / false."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            t, f = self.guard(test.operand)
            return f, t
        if isinstance(test, ast.BoolOp):
            parts = [self.guard(v) for v in test.values]
            if isinstance(test.op, ast.And):
                return set().union(*[p[0] for p in parts]), set()
            return set(), set().union(*[p[1] for p in parts])
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op, left, right = test.ops[0], test.left, test.comparators[0]
            key = name_key(left)
            clean: Set[str] = set()
            if isinstance(op, (ast.In, ast.NotIn)):
                if key and (self._is_literal_collection(right) or
                            (isinstance(right, ast.Name) and right.id in self.consts)):
                    clean = {key}
                elif isinstance(right, ast.Attribute) and right.attr == "parents" and name_key(right.value):
                    clean = {name_key(right.value)}
                return (clean, set()) if isinstance(op, ast.In) else (set(), clean)
            if isinstance(op, (ast.Eq, ast.NotEq)) and key and isinstance(right, ast.Constant):
                return (({key}, set()) if isinstance(op, ast.Eq) else (set(), {key}))
            return set(), set()
        if isinstance(test, ast.Call):
            func = test.func
            base = func.attr if isinstance(func, ast.Attribute) else dotted(func)
            if base in VALIDATORS:
                names: Set[str] = set()
                if isinstance(func, ast.Attribute) and name_key(func.value) and base != "match":
                    names.add(name_key(func.value))
                for a in test.args:
                    if name_key(a):
                        names.add(name_key(a))
                return names, set()
        return set(), set()

    # ---- expression evaluation ---------------------------------------------------------
    def ev(self, node, env, ctx) -> Optional[Taint]:
        if node is None:
            return None
        m = getattr(self, "ev_" + type(node).__name__, None)
        if m:
            return m(node, env, ctx)
        t = None
        for c in ast.iter_child_nodes(node):
            if isinstance(c, ast.expr):
                t = merge(t, self.ev(c, env, ctx))
        return t

    def ev_Constant(self, node, env, ctx):
        return None

    def ev_Name(self, node, env, ctx):
        return env.get(node.id)

    def ev_Attribute(self, node, env, ctx):
        d = dotted(node)
        if is_source_name(d):
            return Taint(src=True, trace=((node.lineno, f"untrusted input `{d}`"),))
        if d and d in env:
            return env[d]
        return self.ev(node.value, env, ctx)

    def ev_Subscript(self, node, env, ctx):
        t = self.ev(node.value, env, ctx)
        self.ev(node.slice, env, ctx)
        return t

    def ev_BinOp(self, node, env, ctx):
        t = merge(self.ev(node.left, env, ctx), self.ev(node.right, env, ctx))
        if t is not None and isinstance(node.op, (ast.Add, ast.Mod)) and self._has_sql(node):
            t = replace(t, sql=True)
        return t

    def ev_JoinedStr(self, node, env, ctx):
        t = None
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                t = merge(t, self.ev(v.value, env, ctx))
        if t is not None and self._has_sql(node):
            t = replace(t, sql=True)
        return t

    def ev_Compare(self, node, env, ctx):
        self.ev(node.left, env, ctx)
        for c in node.comparators:
            self.ev(c, env, ctx)
        return None

    def ev_UnaryOp(self, node, env, ctx):
        t = self.ev(node.operand, env, ctx)
        return None if isinstance(node.op, ast.Not) else t

    def ev_IfExp(self, node, env, ctx):
        self.ev(node.test, env, ctx)
        return merge(self.ev(node.body, env, ctx), self.ev(node.orelse, env, ctx))

    def ev_Lambda(self, node, env, ctx):
        return None

    def ev_NamedExpr(self, node, env, ctx):
        t = self.ev(node.value, env, ctx)
        self.bind(node.target, t, env, node.lineno)
        return t

    def ev_Dict(self, node, env, ctx):
        t = None
        for k in node.keys:
            if k is not None:
                self.ev(k, env, ctx)
        for v in node.values:
            t = merge(t, self.ev(v, env, ctx))
        return t

    def _comprehension(self, node, elts, env, ctx):
        local = dict(env)
        for g in node.generators:
            self.bind(g.target, self.ev(g.iter, local, ctx), local, node.lineno)
            for cond in g.ifs:
                self.ev(cond, local, ctx)
        t = None
        for e in elts:
            t = merge(t, self.ev(e, local, ctx))
        return t

    def ev_ListComp(self, node, env, ctx):
        return self._comprehension(node, [node.elt], env, ctx)

    ev_SetComp = ev_GeneratorExp = ev_ListComp

    def ev_DictComp(self, node, env, ctx):
        return self._comprehension(node, [node.key, node.value], env, ctx)

    # ---- calls ---------------------------------------------------------------------------
    def ev_Call(self, node, env, ctx):
        func = node.func
        name = dotted(func)
        arg_nodes = [a.value if isinstance(a, ast.Starred) else a for a in node.args]
        arg_ts = [self.ev(a, env, ctx) for a in arg_nodes]
        kw_ts: Dict[str, Optional[Taint]] = {}
        extra = None
        for k in node.keywords:
            t = self.ev(k.value, env, ctx)
            if k.arg:
                kw_ts[k.arg] = t
            else:
                extra = merge(extra, t)
        base = func.attr if isinstance(func, ast.Attribute) else name
        recv_t = None
        if isinstance(func, ast.Attribute):
            if is_source_name(name):
                return Taint(src=True, trace=((node.lineno, f"untrusted input `{name}()`"),))
            recv_t = self.ev(func.value, env, ctx)
        elif not isinstance(func, ast.Name):
            self.ev(func, env, ctx)
        if name in SOURCE_CALLS or (isinstance(func, ast.Attribute) and base in SOURCE_METHODS) \
                or name.startswith("sys.stdin."):
            return Taint(src=True, trace=((node.lineno, f"untrusted input `{name or base}()`"),))

        self.check_sinks(node, name, base, arg_nodes, arg_ts, kw_ts, recv_t, ctx)

        info = self.lookup_summary(func, base)
        if info is not None:
            return self.apply_summary(info, node, arg_ts, kw_ts, ctx)

        if name in CLEAN_ALL or name.startswith(CLEAN_PREFIXES):
            return None
        res = None
        if recv_t is not None and (recv_t.src or base in PROPAGATING_METHODS):
            res = recv_t
        for t in arg_ts + list(kw_ts.values()) + [extra]:
            res = merge(res, t)
        safe = SAFE_FOR.get(name) or SAFE_FOR.get(base)
        if safe and res is not None:
            res = replace(res, safe=res.safe | frozenset(safe))
        if res is not None and base in ("format", "join") and any(self._has_sql(a) for a in [func] + arg_nodes):
            res = replace(res, sql=True)
        return res

    def lookup_summary(self, func, base):
        if isinstance(func, ast.Name):
            return self.summaries.get(func.id)
        if isinstance(func, ast.Attribute) and dotted(func.value) in ("self", "cls"):
            return self.summaries.get(func.attr)
        return None

    def apply_summary(self, info, node, arg_ts, kw_ts, ctx):
        incoming: Dict[int, Taint] = {}
        has_star = any(isinstance(a, ast.Starred) for a in node.args)
        if not has_star:
            for i, t in enumerate(arg_ts):
                if t is not None:
                    incoming[i] = t
        for k, t in kw_ts.items():
            if t is not None and k in info.params:
                incoming[info.params.index(k)] = t
        for idx, entries in info.sinks.items():
            t = incoming.get(idx)
            if t is None:
                continue
            for rule, sink_line, desc in entries:
                if rule in t.safe:
                    continue
                if t.src:
                    trace = list(t.trace) + [(node.lineno, f"passed to {info.name}()"),
                                             (sink_line, f"{info.name}() passes it to {desc}")]
                    self.add(rule, node, "High",
                             f"Untrusted input is passed to `{info.name}()`, which sends it to {desc} (line {sink_line}).",
                             trace=trace)
                elif t.params:
                    for p in t.params:
                        ctx.sinks.setdefault(p, set()).add((rule, sink_line, desc))
        res = None
        if info.ret is not None:
            for idx in info.ret.params:
                res = merge(res, incoming.get(idx))
            if info.ret.src:
                res = merge(res, Taint(src=True, trace=((node.lineno, f"{info.name}() returns untrusted data"),)))
            if res is not None and info.ret.safe:
                res = replace(res, safe=res.safe | info.ret.safe)
        return res

    # ---- sinks ---------------------------------------------------------------------------
    def check_sinks(self, node, name, base, arg_nodes, arg_ts, kw_ts, recv_t, ctx):
        a0 = arg_ts[0] if arg_ts else None
        kwget = kw_ts.get

        # SC001 SQL injection: only the *query string* argument matters; parameters are fine
        if base in SQL_METHODS and (arg_nodes or "sql" in kw_ts or "query" in kw_ts):
            q = a0 if arg_nodes else (kwget("sql") or kwget("query"))
            self.hit("SC001", node, q, f"a SQL query (`{name or base}()`)", ctx, need_sql=True)

        # SC002 command injection
        if name in OS_COMMAND:
            self.hit("SC002", node, a0, f"a shell command (`{name}()`)", ctx)
        elif (name.startswith("subprocess.") and base in SUBPROCESS_FUNCS) or name in ("Popen", "check_output", "check_call"):
            # Without shell=True an argument *list* cannot inject extra commands, so only shell=True counts.
            if self._truthy_kw(node, "shell"):
                self.hit("SC002", node, a0 or kwget("args"), f"a shell command (`{name}(..., shell=True)`)", ctx)

        # SC005 dynamic evaluation
        if name in ("eval", "exec", "builtins.eval", "builtins.exec") and arg_nodes:
            if isinstance(arg_nodes[0], ast.Constant):
                pass
            elif a0 is not None and (a0.src or a0.params) and "SC005" not in a0.safe:
                self.hit("SC005", node, a0, f"`{name}()`", ctx)
            else:
                self.weak("SC005", node, "Low", f"`{name}()` evaluates a non-literal expression; verify it is never user-controlled.")

        # SC006 path traversal
        if name in PATH_FUNCS_1 and arg_nodes:
            self.hit("SC006", node, a0, f"a filesystem path (`{name}()`)", ctx)
        elif name in PATH_FUNCS_ALL:
            for t in arg_ts[:2]:
                self.hit("SC006", node, t, f"a filesystem path (`{name}()`)", ctx)
        elif base in PATH_METHODS and isinstance(node.func, ast.Attribute):
            self.hit("SC006", node, recv_t, f"a filesystem path (`.{base}()`)", ctx)

        # SC010 SSRF
        if (name.startswith(("requests.", "httpx.")) and base in HTTP_METHODS) or name in URL_OPEN:
            idx = 1 if base == "request" and len(arg_nodes) > 1 else 0
            url_t = arg_ts[idx] if len(arg_ts) > idx else kwget("url")
            url_node = arg_nodes[idx] if len(arg_nodes) > idx else None
            if url_t is not None and not self._path_only(url_node):
                self.hit("SC010", node, url_t, f"an outbound HTTP request URL (`{name}()`)", ctx)

        # SC003 XSS / SC014 SSTI / SC011 redirect
        if base in XSS_SINKS and arg_nodes:
            if base in ("Markup", "mark_safe") or a0 is not None and (a0.src or self._has_html_literal(arg_nodes[0])):
                self.hit("SC003", node, a0, f"an HTML response (`{base}()`)", ctx)
        if base == "render_template_string" or (base == "Template" and ({"jinja2", "mako"} & self.imports)) \
                or base == "from_string":
            self.hit("SC014", node, a0, f"a template compiled from data (`{base}()`)", ctx)
        if base in REDIRECTS and arg_nodes and not self._path_only(arg_nodes[0]):
            self.hit("SC011", node, a0, f"a redirect target (`{base}()`)", ctx)

        # SC008 deserialization
        if name in UNSAFE_DESER:
            if a0 is not None and (a0.src or a0.params):
                self.hit("SC008", node, a0, f"an unsafe deserializer (`{name}()`)", ctx)
            else:
                self.weak("SC008", node, "Low", f"`{name}()` can execute code when given untrusted data.")
        elif name in ("yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.full_load"):
            loader = kwget("Loader")
            loader_node = next((k.value for k in node.keywords if k.arg == "Loader"), None)
            if loader_node is None and len(arg_nodes) > 1:
                loader_node = arg_nodes[1]
            safe_loader = loader_node is not None and dotted(loader_node).endswith(SAFE_YAML_LOADERS)
            if not safe_loader:
                if a0 is not None and (a0.src or a0.params):
                    self.hit("SC008", node, a0, f"`{name}()` without SafeLoader", ctx)
                else:
                    self.weak("SC008", node, "Medium", f"`{name}()` without SafeLoader can construct arbitrary objects; use yaml.safe_load.")

    # ---- small helpers ---------------------------------------------------------------------
    @staticmethod
    def _truthy_kw(node, name) -> bool:
        for k in node.keywords:
            if k.arg == name and isinstance(k.value, ast.Constant) and k.value.value:
                return True
        return False

    @staticmethod
    def _has_sql(node) -> bool:
        return any(isinstance(n, ast.Constant) and isinstance(n.value, str) and SQL_HINT.search(n.value)
                   for n in ast.walk(node))

    @staticmethod
    def _has_html_literal(node) -> bool:
        return any(isinstance(n, ast.Constant) and isinstance(n.value, str) and "<" in n.value and ">" in n.value
                   for n in ast.walk(node))

    @staticmethod
    def _path_only(node) -> bool:
        """True when a URL expression starts with a fixed scheme+host, so users only control the path."""
        leaf = node
        while True:
            if isinstance(leaf, ast.BinOp):
                leaf = leaf.left
            elif isinstance(leaf, ast.JoinedStr) and leaf.values:
                leaf = leaf.values[0]
            else:
                break
        return (isinstance(leaf, ast.Constant) and isinstance(leaf.value, str)
                and re.match(r"^[a-z][a-z0-9+.\-]*://[^/\s]+", leaf.value, re.I) is not None)

    # ---- syntactic (non-taint) checks ------------------------------------------------------
    def syntactic_checks(self):
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Call):
                self._check_call(n)
            elif isinstance(n, ast.Attribute):
                d = dotted(n)
                if d in ("ssl._create_unverified_context", "ssl.CERT_NONE"):
                    self.weak("SC009", n, "High", f"`{d}` disables TLS certificate verification.")
            elif isinstance(n, ast.Assign):
                self._check_assign(n)
            elif isinstance(n, ast.AnnAssign) and n.value is not None:
                self._check_assign(n)
            elif isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        self._secret(k.value, v, getattr(v, 'lineno', n.lineno))
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and SECURITY_NAME.search(n.name):
                for r in ast.walk(n):
                    if isinstance(r, ast.Return) and r.value is not None and self._uses_weak_random(r.value):
                        self.weak("SC013", r, "Medium", f"`{n.name}()` derives a security value from the predictable `random` module.")

    def _secret(self, name, value_node, line):
        if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
            conf = sec.classify(name, value_node.value)
            if conf:
                text = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
                self.add("SC004", value_node, conf,
                         f"`{name}` is assigned a string literal that looks like a credential.",
                         evidence=sec.redact(text, value_node.value)[:220], line=line)

    def _uses_weak_random(self, node) -> bool:
        for c in ast.walk(node):
            if isinstance(c, ast.Call):
                d = dotted(c.func)
                if d.startswith("random.") and "SystemRandom" not in d:
                    return True
        return False

    def _check_assign(self, n):
        targets = n.targets if isinstance(n, ast.Assign) else [n.target]
        for t in targets:
            key = name_key(t) if isinstance(t, (ast.Name, ast.Attribute)) else None
            if key:
                last = key.split(".")[-1]
                self._secret(last, n.value, n.lineno)
                if SECURITY_NAME.search(last) and self._uses_weak_random(n.value):
                    self.weak("SC013", n, "Medium", f"`{last}` is created with the predictable `random` module; use `secrets`.")
                if last == "DEBUG" and isinstance(n.value, ast.Constant) and n.value.value is True:
                    self.weak("SC012", n, "Medium", "DEBUG = True enables verbose errors and must not ship to production.")
                if last == "ALLOWED_HOSTS" and isinstance(n.value, (ast.List, ast.Tuple)) and \
                        any(isinstance(e, ast.Constant) and e.value == "*" for e in n.value.elts):
                    self.weak("SC012", n, "Medium", "ALLOWED_HOSTS = ['*'] disables Host header validation.", severity="Low")
                if last == "check_hostname" and isinstance(n.value, ast.Constant) and n.value.value is False:
                    self.weak("SC009", n, "High", "check_hostname = False disables TLS hostname verification.")

    def _check_call(self, n):
        name = dotted(n.func)
        base = n.func.attr if isinstance(n.func, ast.Attribute) else name
        kws = {k.arg: k.value for k in n.keywords if k.arg}
        for k, v in kws.items():
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                self._secret(k, v, n.lineno)
        v = kws.get("verify")
        if isinstance(v, ast.Constant) and v.value is False:
            self.weak("SC009", n, "High", "verify=False disables certificate/signature verification.")
        opts = kws.get("options")
        if isinstance(opts, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == "verify_signature"
                                               and isinstance(val, ast.Constant) and val.value is False
                                               for k, val in zip(opts.keys, opts.values)):
            self.weak("SC009", n, "High", "JWT signature verification is disabled (verify_signature=False).")
        # SC007 weak hashes
        weak_hash = name in ("hashlib.md5", "hashlib.sha1", "MD5.new", "SHA.new", "SHA1.new") or (
            name == "hashlib.new" and n.args and isinstance(n.args[0], ast.Constant)
            and str(n.args[0].value).lower() in ("md5", "sha1", "md4"))
        if weak_hash and not (isinstance(kws.get("usedforsecurity"), ast.Constant) and kws["usedforsecurity"].value is False):
            ctx_text = ast.dump(n)
            conf = "High" if SECURITY_NAME.search(ctx_text) else "Medium"
            self.weak("SC007", n, conf, f"`{name}()` is a broken hash; do not use it for passwords, signatures or integrity.")
        # SC012 insecure configuration
        if base == "run" and isinstance(n.func, ast.Attribute):
            d = kws.get("debug")
            if isinstance(d, ast.Constant) and d.value is True:
                self.weak("SC012", n, "High", "Running with debug=True exposes an interactive debugger/stack traces.")
            h = kws.get("host")
            if isinstance(h, ast.Constant) and h.value == "0.0.0.0":
                self.weak("SC012", n, "Medium", "Binding to 0.0.0.0 exposes the service on every network interface.", severity="Low")
        if name == "tempfile.mktemp":
            self.weak("SC012", n, "Medium", "tempfile.mktemp is race-prone; use mkstemp/NamedTemporaryFile.", severity="Low")

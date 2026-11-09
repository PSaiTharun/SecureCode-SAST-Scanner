"""Regex + "taint-lite" analyzer for JavaScript/TypeScript, Java, PHP and Go.

(Also used as the fallback for Python files that cannot be parsed, e.g. Python 2.)

This is deliberately *not* a full parser.  To stay useful and reduce noise it adds
three things on top of plain pattern matching:

* **Variable taint tracking per file** - ``q = req.query.name`` marks ``q`` as untrusted
  from that line on; passing ``q`` to a sink later is reported with a source->sink trace.
* **Context-aware sanitizers** - ``htmlspecialchars`` clears XSS but not SQL injection,
  ``parseInt``/``intval`` clear everything, ``path.basename`` clears path traversal, ...
* **Per-language sinks** - e.g. Go's ``exec.Command`` is only dangerous in ``sh -c`` form,
  JS ``regex.exec()`` is not ``child_process.exec()``, SQL strings need SQL keywords.

Limits (see docs/ARCHITECTURE.md): analysis is line-oriented and flow-insensitive, tracks
only plain variables (not object fields), and does not follow calls across functions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple

from . import secret_rules as sec
from .rules import make_finding

LANG_BY_EXT = {
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js",
    ".java": "java", ".php": "php", ".go": "go", ".py": "py",
}
CONF_RANK = {"Low": 1, "Medium": 2, "High": 3}
TOKEN = re.compile(r"[$@]?[A-Za-z_][\w$]*")
STRING_LIT = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`')
SQL_KW = re.compile(
    r"\b(?:select\b.+\bfrom|insert\s+into|update\b.+\bset|delete\s+from|drop\s+table|union\s+select|"
    r"where|order\s+by)\b", re.I)
_SQL_START = r"\s*(?:select\b.*?\bfrom|insert\s+into|update\b.*?\bset|delete\s+from)\b"
# a quoted SQL string (the closing quote must be the *same* quote char that opened it) joined to dynamic data
SQL_LITERAL_CONCAT = re.compile(
    r"""(?P<q>["'`])""" + _SQL_START + r"""(?:(?!(?P=q)).)*(?P=q)\s*(?:\+|\.)\s*[$\w(]""", re.I)
SQL_LITERAL_INTERP = re.compile(
    r"""(?P<q>["'`])""" + _SQL_START + r"""(?:(?!(?P=q)).)*(?:\$\{|\$[A-Za-z_])""", re.I)
PATH_ONLY_URL = re.compile(r"""^\s*['"`][a-z][a-z0-9+.\-]*://[^/'"`\s]+""", re.I)
SECURITY_CONTEXT = re.compile(r"(?:token|passw|secret|salt|otp|nonce|session|api_?key|csrf|reset|verif|auth|hmac|sign)", re.I)
LITERAL_ARG = re.compile(r"""^\s*(?:"[^"]*"|'[^']*'|`[^`$]*`)\s*[,)]""")


@dataclass
class Profile:
    source: Pattern
    sanitizers: List[Tuple[Pattern, Optional[frozenset]]]
    dynamic: Pattern
    assigns: List[Pattern]
    line_comments: Tuple[str, ...]
    block_comments: bool = True

    def sanitize_effect(self, text: str):
        """Return (clears_everything, rule_ids_cleared) for sanitizer calls found in ``text``."""
        safe: set = set()
        for pat, rules in self.sanitizers:
            if pat.search(text):
                if rules is None:
                    return True, frozenset()
                safe |= rules
        return False, frozenset(safe)


def _fs(*ids):
    return frozenset(ids)


XSS, SQLI, CMD, PATH, REDIR = _fs("SC003"), _fs("SC001"), _fs("SC002"), _fs("SC006"), _fs("SC011")

PROFILES: Dict[str, Profile] = {
    "js": Profile(
        source=re.compile(
            r"\b(?:req|request)\.(?:query|body|params|headers|cookies|files|url|originalUrl|path|hostname)\b|"
            r"\bprocess\.argv\b|\blocation\.(?:search|hash|href)\b|\bdocument\.(?:cookie|URL|referrer)\b|"
            r"\bwindow\.name\b"),
        sanitizers=[
            (re.compile(r"\b(?:parseInt|parseFloat|Number|Boolean)\s*\(|\.length\b"), None),
            (re.compile(r"encodeURIComponent|escapeHtml|\bescape\s*\(|_\.escape|DOMPurify|sanitizeHtml|validator\.escape|\bxss\s*\("), XSS),
            (re.compile(r"path\.basename"), PATH),
            (re.compile(r"shell-quote|shellescape|escapeShell"), CMD),
            (re.compile(r"\.escape(?:Id)?\s*\(|sqlstring"), SQLI),
        ],
        dynamic=re.compile(r"\+|\$\{|\.concat\s*\(|util\.format"),
        assigns=[
            re.compile(r"(?:^|[;{}])\s*(?:export\s+)?(?:(?:const|let|var)\s+)?(?P<names>[A-Za-z_$][\w$]*)\s*"
                       r"(?::\s*[\w<>\[\]|. ]+?)?\s*(?P<op>\+?=)(?![=>])\s*(?P<rhs>[^;]*)"),
            re.compile(r"(?:const|let|var)\s*\{(?P<names>[^}]*)\}\s*(?P<op>=)\s*(?P<rhs>[^;]*)"),
        ],
        line_comments=("//",),
    ),
    "java": Profile(
        source=re.compile(
            r"\b(?:request|req)\.(?:getParameter|getParameterValues|getParameterMap|getHeader|getQueryString|"
            r"getCookies|getInputStream|getReader|getRequestURI|getPathInfo)\s*\(|@RequestParam|\bargs\s*\["),
        sanitizers=[
            (re.compile(r"Integer\.parseInt|Long\.parseLong|Double\.parseDouble|UUID\.fromString|Boolean\.parseBoolean"), None),
            (re.compile(r"StringEscapeUtils|escapeHtml|HtmlUtils\.htmlEscape|Encode\.for(?:Html|HtmlAttribute|JavaScript)|URLEncoder\.encode"), XSS),
            (re.compile(r"FilenameUtils\.getName|\.getFileName\s*\(\)"), PATH),
            (re.compile(r"ESAPI\.encoder\(\)\.encodeForSQL"), SQLI),
        ],
        dynamic=re.compile(r"\+|String\.format|\.formatted\s*\(|\.concat\s*\(|\.append\s*\("),
        assigns=[re.compile(r"(?:^|[;{}])\s*(?:final\s+)?(?:[\w.<>\[\],?]+\s+)?(?P<names>[A-Za-z_]\w*)\s*"
                            r"(?P<op>\+?=)(?![=>])\s*(?P<rhs>[^;]*)")],
        line_comments=("//",),
    ),
    "php": Profile(
        source=re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\b|\$HTTP_(?:GET|POST)_VARS|php://input"),
        sanitizers=[
            (re.compile(r"\b(?:intval|floatval|is_numeric|ctype_\w+|filter_var)\s*\(|\(\s*int\s*\)", re.I), None),
            (re.compile(r"\b(?:htmlspecialchars|htmlentities|strip_tags|esc_html|esc_attr|wp_kses)\s*\(", re.I), XSS),
            (re.compile(r"\b(?:escapeshellarg|escapeshellcmd)\s*\(", re.I), CMD),
            (re.compile(r"\b(?:basename|realpath)\s*\(", re.I), PATH),
            (re.compile(r"real_escape_string|mysqli_real_escape_string|addslashes|pg_escape_string|->quote\s*\(", re.I), SQLI),
            (re.compile(r"\b(?:urlencode|rawurlencode)\s*\(", re.I), _fs("SC003", "SC002")),
        ],
        dynamic=re.compile(r"""["']\s*\.\s*[$\w(]|[$\w)\]]\s*\.\s*["']|"[^"]*\$\w|"[^"]*\{\$|\bsprintf\s*\(""", re.I),
        assigns=[re.compile(r"(?:^|[;{}])\s*(?P<names>\$\w+)\s*(?P<op>\.?=)(?![=>])\s*(?P<rhs>[^;]*)")],
        line_comments=("//", "#"),
    ),
    "go": Profile(
        source=re.compile(
            r"\b(?:r|req|request)\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue|URL\.Path|URL\.RawQuery|Header\.Get|Cookie)\b|"
            r"\bmux\.Vars\s*\(|\bos\.Args\b|\bc\.(?:Query|Param|PostForm|GetHeader|DefaultQuery)\s*\("),
        sanitizers=[
            (re.compile(r"\bstrconv\.(?:Atoi|ParseInt|ParseFloat|ParseBool)\b"), None),
            (re.compile(r"html\.EscapeString|template\.(?:HTMLEscapeString|JSEscapeString)|url\.(?:QueryEscape|PathEscape)"), XSS),
            (re.compile(r"filepath\.Base|\bpath\.Base"), PATH),
        ],
        dynamic=re.compile(r"\+|fmt\.Sprintf|fmt\.Sprint\b|strings\.Join"),
        assigns=[re.compile(r"^\s*(?:var\s+)?(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?P<op>:=|=)(?![=>])\s*(?P<rhs>.+)$")],
        line_comments=("//",),
    ),
    "py": Profile(
        source=re.compile(r"\brequest\.(?:args|form|values|json|data|headers|cookies|files|GET|POST|META|COOKIES|body)\b|"
                          r"\binput\s*\(|\bsys\.argv\b"),
        sanitizers=[
            (re.compile(r"\b(?:int|float|bool|len)\s*\("), None),
            (re.compile(r"html\.escape|\bescape\s*\(|bleach\.clean"), XSS),
            (re.compile(r"shlex\.quote|pipes\.quote"), CMD),
            (re.compile(r"secure_filename|os\.path\.basename"), PATH),
        ],
        dynamic=re.compile(r"\+|\bf[\"']|%\s*[(\w]|\.format\s*\("),
        assigns=[re.compile(r"^\s*(?P<names>[A-Za-z_]\w*)\s*(?P<op>\+?=)(?!=)\s*(?P<rhs>.+)$")],
        line_comments=("#",), block_comments=False,
    ),
}


@dataclass
class Spec:
    rule: str
    langs: Tuple[str, ...]
    sink: Pattern
    desc: str
    mode: str = "dyn"            # dyn | taint | eval | always
    sql: bool = False            # dyn: dynamic data alone only counts if SQL keywords are present
    direct: bool = True          # dyn: a tainted value passed directly is already dangerous
    html: bool = False           # taint: also report HTML-literal + dynamic data at Medium
    conf: str = "Medium"         # always: confidence (boosted to High if ``boost`` matches the line)
    boost: Optional[Pattern] = None
    needs: Optional[Pattern] = None       # must match the text after the sink
    file_needs: Optional[Pattern] = None  # must match somewhere in the file
    context: Optional[Pattern] = None     # must match the line (e.g. security-relevant variable name)


def _c(p, flags=0):
    return re.compile(p, flags)


SQL_CALL = (r"(?<![\w$])(?:execute|executeQuery|executeUpdate|executemany|query|queryRaw|\$queryRaw|\$executeRaw|raw|"
            r"prepare|prepareStatement|createQuery|createNativeQuery|queryForList|queryForObject|"
            r"Exec|Query|QueryRow|mysqli_query|mysql_query|pg_query|sqlsrv_query|find_by_sql)\s*\(")

SPECS: List[Spec] = [
    # ---- SC001 SQL injection ------------------------------------------------------------
    Spec("SC001", ("js", "java", "php", "go", "py"), _c(SQL_CALL, re.I), "a SQL query", sql=True, direct=False),
    # ---- SC002 command injection --------------------------------------------------------
    Spec("SC002", ("js",), _c(r"(?<![\w.$])(?:exec|execSync)\s*\(|\b(?:child_process|cp)\.(?:exec|execSync)\s*\("), "a shell command"),
    Spec("SC002", ("java",), _c(r"Runtime\.getRuntime\(\)\.exec\s*\(|\bnew\s+ProcessBuilder\s*\("), "a process command"),
    Spec("SC002", ("php",), _c(r"\b(?:shell_exec|system|exec|passthru|popen|proc_open|pcntl_exec)\s*\(", re.I), "a shell command"),
    Spec("SC002", ("php",), _c(r"`[^`\n]*\$\w"), "a backtick shell command", mode="taint"),
    Spec("SC002", ("go",),
         _c(r"""\bexec\.Command(?:Context)?\s*\(\s*(?:\w+\s*,\s*)?["'](?:sh|bash|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?)["']\s*,\s*["'][-/]?\w+["']\s*,"""),
         "a shell command (`sh -c`)"),
    Spec("SC002", ("py",), _c(r"\bos\.(?:system|popen)\s*\("), "a shell command"),
    Spec("SC002", ("py",), _c(r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\("), "a shell command",
         needs=_c(r"shell\s*=\s*True")),
    # ---- SC003 XSS ---------------------------------------------------------------------
    Spec("SC003", ("js",), _c(r"\.(?:innerHTML|outerHTML)\s*=(?!=)|\bdocument\.write(?:ln)?\s*\(|\.insertAdjacentHTML\s*\(|dangerouslySetInnerHTML"),
         "a DOM/HTML sink"),
    Spec("SC003", ("js",), _c(r"\bres\.(?:send|write|end)\s*\(|\.(?:html|append|prepend)\s*\("), "an HTML response", mode="taint", html=True),
    Spec("SC003", ("php",), _c(r"\b(?:echo|print|printf)\b|<\?=", re.I), "HTML output", mode="taint", html=True),
    Spec("SC003", ("java",), _c(r"\bgetWriter\(\)\.(?:print|println|write|printf)\s*\(|\bout\.(?:print|println|write)\s*\("), "an HTML response", mode="taint", html=True),
    Spec("SC003", ("go",), _c(r"\bfmt\.Fprint(?:f|ln)?\s*\(\s*w\b|\bw\.Write\s*\(|\bio\.WriteString\s*\(\s*w\b|\bc\.(?:String|HTML)\s*\("),
         "an HTML response", mode="taint", html=True),
    Spec("SC003", ("py",), _c(r"\bMarkup\s*\(|\bmark_safe\s*\(|\bHttpResponse\s*\(|\bmake_response\s*\("), "an HTML response", mode="taint"),
    # ---- SC005 dynamic evaluation ---------------------------------------------------------
    Spec("SC005", ("js",), _c(r"(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(|(?<![\w.$])Function\s*\("), "`eval`/`Function`", mode="eval"),
    Spec("SC005", ("php",), _c(r"(?<![\w>:$])eval\s*\(", re.I), "`eval`", mode="eval"),
    Spec("SC005", ("java",), _c(r"\b(?:engine|scriptEngine|jsEngine|nashorn)\.eval\s*\(|GroovyShell\s*\(\s*\)\s*\.evaluate\s*\("), "a script engine", mode="eval"),
    Spec("SC005", ("py",), _c(r"(?<![\w.])(?:eval|exec)\s*\("), "`eval`/`exec`", mode="eval"),
    # ---- SC006 path traversal / file inclusion ----------------------------------------------
    Spec("SC006", ("js",), _c(r"(?<![\w$])(?:fs\.(?:promises\.)?)?(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|"
                              r"appendFileSync|unlink|unlinkSync|readdir|readdirSync|rmdir|rmSync|createWriteStream)\s*\("), "a filesystem path"),
    Spec("SC006", ("js",), _c(r"\bres\.(?:sendFile|download)\s*\(|\bpath\.(?:join|resolve)\s*\("), "a filesystem path", mode="taint"),
    Spec("SC006", ("java",), _c(r"\bnew\s+(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\(|\bPaths\.get\s*\(|\bPath\.of\s*\(|"
                                r"\bFiles\.(?:read\w*|write\w*|newInputStream|newOutputStream|newBufferedReader|delete\w*|copy|move|list|walk)\s*\("), "a filesystem path"),
    Spec("SC006", ("php",), _c(r"\b(?:fopen|file_get_contents|file_put_contents|readfile|unlink|file|fpassthru|move_uploaded_file|copy|rename|mkdir|rmdir|"
                               r"opendir|scandir|highlight_file|show_source)\s*\(", re.I), "a filesystem path"),
    Spec("SC006", ("php",), _c(r"\b(?:include|include_once|require|require_once)\b", re.I), "an included file", mode="taint"),
    Spec("SC006", ("go",), _c(r"\bos\.(?:Open|OpenFile|ReadFile|Create|Remove|RemoveAll|ReadDir|Mkdir|MkdirAll|Rename)\s*\(|"
                              r"\bioutil\.(?:ReadFile|WriteFile|ReadDir)\s*\(|\bhttp\.ServeFile\s*\("), "a filesystem path"),
    Spec("SC006", ("go",), _c(r"\bfilepath\.Join\s*\("), "a filesystem path", mode="taint"),
    Spec("SC006", ("py",), _c(r"(?<![\w.])open\s*\(|\bos\.(?:remove|unlink|listdir|makedirs|rename)\s*\(|\bshutil\.\w+\s*\(|\bsend_file\s*\("), "a filesystem path"),
    # ---- SC007 weak hash -------------------------------------------------------------------
    Spec("SC007", ("js",), _c(r"createHash\s*\(\s*[\"'](?:md5|sha1|md4)[\"']"), "a weak hash", mode="always", boost=SECURITY_CONTEXT),
    Spec("SC007", ("java",), _c(r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1|MD2|MD4)\""), "a weak hash", mode="always", boost=SECURITY_CONTEXT),
    Spec("SC007", ("php",), _c(r"(?<![\w>:$])(?:md5|sha1)\s*\(", re.I), "a weak hash", mode="always", boost=SECURITY_CONTEXT),
    Spec("SC007", ("go",), _c(r"\b(?:md5|sha1)\.(?:New|Sum)\s*\("), "a weak hash", mode="always", boost=SECURITY_CONTEXT),
    Spec("SC007", ("py",), _c(r"\bhashlib\.(?:md5|sha1)\s*\("), "a weak hash", mode="always", boost=SECURITY_CONTEXT),
    # ---- SC008 insecure deserialization ------------------------------------------------------
    Spec("SC008", ("java",), _c(r"\bnew\s+ObjectInputStream\s*\(|\bnew\s+XMLDecoder\s*\(|\.enableDefaultTyping\s*\(|new\s+Yaml\s*\(\s*\)\s*\.load"),
         "an unsafe deserializer", mode="always", boost=re.compile(r"request|getInputStream|getParameter")),
    Spec("SC008", ("php",), _c(r"\bunserialize\s*\(", re.I), "`unserialize`", mode="always"),
    Spec("SC008", ("js",), _c(r"(?<![\w$])unserialize\s*\(|node-serialize"), "an unsafe deserializer", mode="always"),
    Spec("SC008", ("py",), _c(r"\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Safe)"), "an unsafe deserializer", mode="always"),
    # ---- SC009 verification disabled ---------------------------------------------------------
    Spec("SC009", ("js",), _c(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*\]?\s*=\s*[\"']?0|strictSSL\s*:\s*false"),
         "TLS verification", mode="always", conf="High"),
    Spec("SC009", ("java",), _c(r"ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|TrustAllStrategy|TrustSelfSignedStrategy|"
                                r"setHostnameVerifier\s*\([^)]*->\s*true|\(\s*hostname\s*,\s*session\s*\)\s*->\s*true"),
         "TLS verification", mode="always", conf="High"),
    Spec("SC009", ("php",), _c(r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)|[\"']verify(?:_peer(?:_name)?)?[\"']\s*=>\s*false", re.I),
         "TLS verification", mode="always", conf="High"),
    Spec("SC009", ("go",), _c(r"InsecureSkipVerify\s*:\s*true"), "TLS verification", mode="always", conf="High"),
    Spec("SC009", ("py",), _c(r"verify\s*=\s*False"), "TLS verification", mode="always", conf="High"),
    # ---- SC010 SSRF ------------------------------------------------------------------------
    Spec("SC010", ("js",), _c(r"(?<![\w$.])(?:fetch|axios|got|superagent|needle)\s*\(|\b(?:axios|got|needle|superagent|request|http|https)\.(?:get|post|put|delete|patch|request|head)\s*\("),
         "an outbound request URL", mode="taint"),
    Spec("SC010", ("java",), _c(r"\bnew\s+URL\s*\(|\bURI\.create\s*\(|\bnew\s+(?:HttpGet|HttpPost)\s*\("), "an outbound request URL", mode="taint"),
    Spec("SC010", ("php",), _c(r"\b(?:curl_init|file_get_contents|get_headers|simplexml_load_file)\s*\(|CURLOPT_URL\s*,", re.I), "an outbound request URL", mode="taint"),
    Spec("SC010", ("go",), _c(r"\bhttp\.(?:Get|Post|Head|PostForm|NewRequest|NewRequestWithContext)\s*\("), "an outbound request URL", mode="taint"),
    Spec("SC010", ("py",), _c(r"\brequests\.(?:get|post|put|delete|head|patch)\s*\(|\burlopen\s*\("), "an outbound request URL", mode="taint"),
    # ---- SC011 open redirect -------------------------------------------------------------------
    Spec("SC011", ("js",), _c(r"\bres\.redirect\s*\(|\b(?:window\.)?location(?:\.href)?\s*=(?!=)|\blocation\.(?:assign|replace)\s*\("), "a redirect target", mode="taint"),
    Spec("SC011", ("java",), _c(r"\bsendRedirect\s*\(|\bnew\s+RedirectView\s*\("), "a redirect target", mode="taint"),
    Spec("SC011", ("php",), _c(r"\bheader\s*\(\s*[\"']Location\s*:", re.I), "a redirect target", mode="taint"),
    Spec("SC011", ("go",), _c(r"\bhttp\.Redirect\s*\("), "a redirect target", mode="taint"),
    Spec("SC011", ("py",), _c(r"\bredirect\s*\(|\bHttpResponseRedirect\s*\("), "a redirect target", mode="taint"),
    # ---- SC012 insecure configuration -------------------------------------------------------------
    Spec("SC012", ("java",), _c(r"\.csrf\s*\(\s*\)\s*\.disable\s*\(|csrf\s*\(\s*\w+\s*->\s*\w+\.disable\s*\(\s*\)\s*\)"), "disabled CSRF protection", mode="always"),
    Spec("SC012", ("js",), _c(r"cors\s*\(\s*\{[^}]*origin\s*:\s*[\"']\*[\"']"), "a wildcard CORS policy", mode="always"),
    Spec("SC012", ("php",), _c(r"display_errors[\"']?\s*[,=]\s*[\"']?(?:1|On|true)", re.I), "verbose error display", mode="always"),
    Spec("SC012", ("py",), _c(r"\bdebug\s*=\s*True"), "debug mode", mode="always"),
    # ---- SC013 insecure randomness ----------------------------------------------------------------
    Spec("SC013", ("js",), _c(r"\bMath\.random\s*\("), "a predictable PRNG", mode="always", context=SECURITY_CONTEXT),
    Spec("SC013", ("java",), _c(r"\bnew\s+Random\s*\(|\bMath\.random\s*\("), "a predictable PRNG", mode="always", context=SECURITY_CONTEXT),
    Spec("SC013", ("php",), _c(r"\b(?:rand|mt_rand|uniqid|lcg_value)\s*\(", re.I), "a predictable PRNG", mode="always", context=SECURITY_CONTEXT),
    Spec("SC013", ("go",), _c(r"\brand\.(?:Int|Intn|Int31|Int63|Float64|Perm|Read)\s*\("), "a predictable PRNG", mode="always",
         context=SECURITY_CONTEXT, file_needs=_c(r'"math/rand"')),
]


@dataclass
class VarInfo:
    safe: frozenset
    sql: bool
    line: int
    source_text: str


class RegexAnalyzer:
    def __init__(self, text: str, path: str, lang: str, skip_secret_names: bool = False):
        self.text = text
        self.lines = text.splitlines()
        self.path = path
        self.lang = lang
        self.prof = PROFILES[lang]
        self.skip_secret_names = skip_secret_names
        self.findings: Dict[Tuple[str, int], object] = {}
        self.tainted: Dict[str, VarInfo] = {}
        self.pending_sql: Dict[str, object] = {}
        self.specs = [s for s in SPECS if lang in s.langs and (s.file_needs is None or s.file_needs.search(text))]

    # ---- helpers ---------------------------------------------------------------------
    def code_lines(self):
        """Yield (line_number, code) skipping comments; block comments are tracked."""
        in_block = False
        for no, raw in enumerate(self.lines, 1):
            line = raw
            if self.prof.block_comments:
                if in_block:
                    if "*/" not in line:
                        continue
                    line = line.split("*/", 1)[1]
                    in_block = False
                line = re.sub(r"/\*.*?\*/", " ", line)
                if "/*" in line:
                    line = line.split("/*", 1)[0]
                    in_block = True
            stripped = line.strip()
            if not stripped or stripped.startswith(self.prof.line_comments):
                continue
            if self.lang == "php" and stripped.startswith(("<?php", "?>")) and len(stripped) <= 5:
                continue
            yield no, line

    def idents(self, text: str) -> set:
        """Identifiers referenced in ``text`` (string-literal contents are ignored, except interpolation)."""
        if self.lang == "php":
            return set(TOKEN.findall(text))
        out = set(TOKEN.findall(STRING_LIT.sub('""', text)))
        for m in re.finditer(r"\$\{([^}]*)\}", text):          # JS template literal interpolation
            out.update(TOKEN.findall(m.group(1)))
        return out

    @staticmethod
    def statement_end(text: str) -> str:
        """Cut ``text`` at the first ';' outside a string so one statement never leaks into the next."""
        quote = None
        for i, ch in enumerate(text):
            if quote:
                if ch == quote and text[i - 1] != "\\":
                    quote = None
            elif ch in "\"'`":
                quote = ch
            elif ch == ";":
                return text[:i]
        return text

    @staticmethod
    def in_string(line: str, pos: int) -> bool:
        """True when ``pos`` is inside a quoted string literal (e.g. MD5() inside an SQL string)."""
        quote = None
        for i, ch in enumerate(line[:pos]):
            if quote:
                if ch == quote and line[i - 1] != "\\":
                    quote = None
            elif ch in "\"'`":
                quote = ch
        return quote is not None

    def leading_controlled(self, rest: str) -> bool:
        """SSRF needs the *start* of the URL (scheme/host) to be user-controlled, not just a path part."""
        head = rest.lstrip().lstrip("(").lstrip()
        if self.prof.source.match(head):
            return True
        m = TOKEN.match(head)
        return bool(m) and m.group(0) in self.tainted

    @staticmethod
    def snippet(line: str, pos: int) -> str:
        s = line.strip()
        if len(s) <= 200:
            return s
        start = max(0, pos - 80)
        return ("..." if start else "") + line[start:start + 180].strip() + "..."

    def add(self, rule, no, conf, evidence, detail, trace, severity=None):
        key = (rule, no)
        old = self.findings.get(key)
        if old is not None and CONF_RANK[old.confidence] >= CONF_RANK[conf]:
            return
        self.findings[key] = make_finding(rule, self.path, no, evidence, conf, detail=detail, trace=trace, severity=severity)

    # ---- main loop -------------------------------------------------------------------
    def run(self):
        for no, line in self.code_lines():
            self.scan_specs(no, line)
            self.scan_sql_literal(no, line)
            self.scan_secrets(no, line)
            self.update_taint(no, line)
        for f in self.pending_sql.values():                  # SQL strings never seen reaching an execute call
            self.findings.setdefault((f.rule_id, f.line), f)
        return list(self.findings.values())

    def evidence_for(self, rule: str, rest: str):
        """Return (source_text or None, [tainted var names], any_sql_built) for the sink arguments."""
        src = self.prof.source.search(rest)
        names = self.idents(rest)
        tvs = [v for v in sorted(names) if v in self.tainted and rule not in self.tainted[v].safe]
        return (src.group(0) if src else None), tvs, any(self.tainted[v].sql for v in tvs)

    def scan_specs(self, no, line):
        for spec in self.specs:
            for m in spec.sink.finditer(line):
                rest = self.statement_end(line[m.end():])
                if spec.needs is not None and not spec.needs.search(rest):
                    continue
                if spec.context is not None and not spec.context.search(line):
                    continue
                if self.lang == "php" and re.match(r"""\s*['"]php://""", rest):
                    continue            # php://input / php://stdin are sources, not paths or URLs
                if spec.mode == "always":
                    if self.in_string(line, m.start()):
                        continue
                    conf = "High" if (spec.boost is not None and spec.boost.search(line)) else spec.conf
                    self.add(spec.rule, no, conf, self.snippet(line, m.start()),
                             f"{spec.desc.capitalize()} detected on this line.", [(no, f"{spec.desc}")])
                    break
                clears, safe = self.prof.sanitize_effect(rest)
                if clears or spec.rule in safe:
                    continue
                src, tvs, sql_built = self.evidence_for(spec.rule, rest)
                has_evidence = bool(src or tvs)
                dynamic = bool(self.prof.dynamic.search(rest))
                conf = None
                if spec.mode == "taint":
                    if spec.rule == "SC010" and (PATH_ONLY_URL.match(rest) or not self.leading_controlled(rest)
                                                 and "CURLOPT_URL" not in line):
                        continue
                    if has_evidence:
                        conf = "High"
                    elif spec.html and dynamic and re.search(r"<\w", rest):
                        conf = "Medium"
                elif spec.mode == "eval":
                    if LITERAL_ARG.match(rest):
                        continue
                    conf = "High" if has_evidence else "Medium"
                else:  # dyn
                    has_sql = bool(SQL_KW.search(rest))
                    if spec.sql:
                        if dynamic and has_sql and has_evidence:
                            conf = "High"
                        elif has_evidence and sql_built:
                            conf = "High"
                        elif dynamic and has_sql:
                            conf = "Medium"
                    else:
                        if has_evidence and (spec.direct or dynamic):
                            conf = "High"
                        elif dynamic:
                            conf = "Medium"
                if conf is None:
                    continue
                trace = []
                for v in tvs:
                    info = self.tainted[v]
                    trace.append((info.line, f"`{v}` derives from untrusted input `{info.source_text}`"))
                    self.pending_sql.pop(v, None)
                if src:
                    trace.append((no, f"untrusted input `{src}`"))
                trace.append((no, f"reaches {spec.desc}"))
                if has_evidence:
                    detail = f"Untrusted input ({src or ', '.join('`'+v+'`' for v in tvs)}) reaches {spec.desc} with no recognised sanitiser."
                else:
                    detail = f"Dynamically built data reaches {spec.desc}; verify that no untrusted input can get there."
                self.add(spec.rule, no, conf, self.snippet(line, m.start()), detail, trace)
                break

    def scan_sql_literal(self, no, line):
        """SQL string built by concatenation/interpolation on an assignment or return line."""
        if ("SC001", no) in self.findings:
            return
        m = SQL_LITERAL_CONCAT.search(line) or SQL_LITERAL_INTERP.search(line)
        if not m:
            return
        src, tvs, _ = self.evidence_for("SC001", line[m.end() - 1:])
        if self.lang in ("js", "go") and not re.search(r"\+|\$\{|Sprintf", line):
            return
        conf = "High" if (src or tvs) else "Medium"
        trace = [(no, "SQL statement built by string concatenation/interpolation")]
        if src:
            trace.insert(0, (no, f"untrusted input `{src}`"))
        f = make_finding("SC001", self.path, no, self.snippet(line, m.start()), conf,
                         detail="A SQL statement is assembled from dynamic data; use parameterized queries.", trace=trace)
        var = self.assigned_name(line)
        if var:
            self.pending_sql[var] = f        # replaced by the execute-site finding if one follows
        else:
            self.findings[("SC001", no)] = f

    def assigned_name(self, line):
        for pat in self.prof.assigns:
            m = pat.search(line)
            if m:
                return m.group("names").split(",")[0].strip()
        return None

    def scan_secrets(self, no, line):
        for label, value in sec.format_hits(line):
            self.add("SC004", no, "High", sec.redact(line.strip(), value)[:220],
                     f"Looks like a {label} committed to source.", [(no, f"{label} in source")])
        if self.skip_secret_names:
            return
        for name, value, conf in sec.assignment_hits(line):
            self.add("SC004", no, conf, sec.redact(line.strip(), value)[:220],
                     f"`{name}` is assigned a string literal that looks like a credential.", [(no, f"`{name}` assigned a literal")])

    def update_taint(self, no, line):
        """Track which plain variables currently hold untrusted data (flow-insensitive, in file order)."""
        for idx, pat in enumerate(self.prof.assigns):
            destructure = self.lang == "js" and idx == 1
            for m in pat.finditer(line):
                rhs, op = m.group("rhs"), m.group("op")
                if destructure:
                    names = [n.split(":")[-1].split("=")[0].strip() for n in m.group("names").split(",")]
                else:
                    names = [n.strip() for n in m.group("names").split(",")]
                clears, safe = self.prof.sanitize_effect(rhs)
                src = self.prof.source.search(rhs)
                tvs = [v for v in self.idents(rhs) if v in self.tainted]
                for name in names:
                    if not name or name in ("_", "err"):
                        continue
                    if clears:
                        self.tainted.pop(name, None)
                    elif src or tvs:
                        inherited = frozenset()
                        if tvs and not src:
                            inherited = frozenset.intersection(*[self.tainted[v].safe for v in tvs])
                        origin = src.group(0) if src else self.tainted[tvs[0]].source_text
                        sql = bool(SQL_KW.search(rhs)) or any(self.tainted[v].sql for v in tvs)
                        self.tainted[name] = VarInfo(frozenset(safe) | inherited, sql, no, origin)
                    elif op not in ("+=", ".="):
                        self.tainted.pop(name, None)

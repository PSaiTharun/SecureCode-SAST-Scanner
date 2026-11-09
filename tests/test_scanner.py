import json
import tempfile
import unittest
from pathlib import Path

from scanner.engine import Scanner
from scanner.reporting import json_text, sarif_dict

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


def scan_snippet(name, code):
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / name).write_text(code, encoding="utf-8")
        findings, n, _ = Scanner().scan(Path(d))
        return findings


def rules(findings):
    return {f.rule_id for f in findings}


class OriginalBehaviour(unittest.TestCase):
    def test_secret(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text('api_key = "not-a-real-secret-value"\n')
            f, n, k = Scanner().scan(Path(d))
            self.assertEqual(n, 1)
            self.assertTrue(any(x.rule_id == "SC004" for x in f))

    def test_suppression(self):
        f = scan_snippet("a.py", 'api_key = "not-a-real-secret-value" # sast:ignore SC004 -- fixture\n')
        self.assertFalse(any(x.rule_id == "SC004" for x in f))

    def test_unsupported(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.txt").write_text('password="secret-value"')
            f, n, _ = Scanner().scan(Path(d))
            self.assertEqual((f, n), ([], 0))


class SamplesGroundTruth(unittest.TestCase):
    EXPECTED = {
        "python_app.py": {"SC001", "SC002", "SC003", "SC004", "SC005", "SC006"},
        "app.js": {"SC001", "SC002", "SC003", "SC004", "SC005"},
        "Example.java": {"SC001", "SC002", "SC004"},
        "app.php": {"SC001", "SC003", "SC004", "SC006"},
        "main.go": {"SC002"},
        "flask_app.py": {"SC001", "SC002", "SC003", "SC008", "SC010", "SC011", "SC012"},
    }

    def test_vulnerable_samples_detected(self):
        found, _, _ = Scanner().scan(SAMPLES / "vulnerable")
        by_file = {}
        for f in found:
            by_file.setdefault(Path(f.file).name, set()).add(f.rule_id)
        for name, expected in self.EXPECTED.items():
            self.assertTrue(expected <= by_file.get(name, set()),
                            f"{name}: missing {expected - by_file.get(name, set())}")

    def test_fixed_samples_clean(self):
        found, _, _ = Scanner().scan(SAMPLES / "fixed")
        self.assertEqual([(f.file, f.line, f.rule_id) for f in found], [])


class PythonTaint(unittest.TestCase):
    def test_source_to_sink_high_confidence_with_trace(self):
        f = scan_snippet("a.py", "import os\nfrom flask import request\n"
                                 "def v():\n    n = request.args['n']\n    os.system('ping ' + n)\n")
        hit = [x for x in f if x.rule_id == "SC002"][0]
        self.assertEqual(hit.confidence, "High")
        self.assertGreaterEqual(len(hit.trace), 3)

    def test_sanitizer_is_context_specific(self):
        code = ("import html, shlex, os\nfrom flask import request\n"
                "def v():\n    n = request.args['n']\n"
                "    os.system('x ' + shlex.quote(n))\n"          # safe for SC002
                "    cursor.execute('SELECT * FROM t WHERE a=' + html.escape(n))\n")  # html.escape != SQL safe
        f = scan_snippet("a.py", code)
        self.assertNotIn("SC002", rules(f))
        self.assertIn("SC001", rules(f))

    def test_parameterized_query_safe(self):
        f = scan_snippet("a.py", "def g(c, uid):\n    c.execute('SELECT * FROM t WHERE id = %s', (uid,))\n")
        self.assertNotIn("SC001", rules(f))

    def test_allowlist_guard(self):
        code = ("import os\nOK = {'a', 'b'}\ndef g(x):\n    if x not in OK:\n        raise ValueError()\n"
                "    os.system('run ' + x)\n")
        self.assertNotIn("SC002", rules(scan_snippet("a.py", code)))

    def test_interprocedural(self):
        code = ("import os\nfrom flask import request\ndef h(c):\n    os.system(c)\n"
                "def v():\n    h(request.args['c'])\n")
        f = [x for x in scan_snippet("a.py", code) if x.rule_id == "SC002"]
        self.assertTrue(any(x.confidence == "High" and x.line == 6 for x in f))

    def test_ssrf_path_only_not_flagged(self):
        code = "import requests\nfrom flask import request\ndef v():\n    requests.get('https://api.x.io/' + request.args['p'])\n"
        self.assertNotIn("SC010", rules(scan_snippet("a.py", code)))

    def test_string_in_comment_or_docstring_ignored(self):
        code = 'def f():\n    """os.system("x" + y) eval(z)"""\n    # eval(code)\n    return 1\n'
        self.assertEqual(scan_snippet("a.py", code), [])

    def test_python2_file_falls_back_to_regex(self):
        f = scan_snippet("old.py", "print 'x'\nos.system('a' + b)\n")
        self.assertIn("SC002", rules(f))


class RegexLanguages(unittest.TestCase):
    def test_js_regex_exec_not_command_injection(self):
        self.assertNotIn("SC002", rules(scan_snippet("a.js", "const m = re.exec(input + x);\n")))

    def test_js_taint_via_variable(self):
        f = scan_snippet("a.js", "const q = req.query.name;\nres.send('<b>' + q + '</b>');\n")
        self.assertEqual([x.confidence for x in f if x.rule_id == "SC003"], ["High"])

    def test_php_sanitizer_clears_xss_only(self):
        f = scan_snippet("a.php", '<?php\n$n = htmlspecialchars($_GET["n"]);\necho $n;\n')
        self.assertNotIn("SC003", rules(f))

    def test_go_exec_without_shell_is_safe(self):
        self.assertEqual(scan_snippet("a.go", 'package m\nfunc f(x string){ exec.Command("ls", "-l", x) }\n'), [])

    def test_java_parameterized_safe(self):
        code = 'class A { void f(java.sql.Connection c, String x) throws Exception { c.prepareStatement("SELECT * FROM t WHERE n=?"); } }\n'
        self.assertNotIn("SC001", rules(scan_snippet("A.java", code)))

    def test_weak_hash_and_tls(self):
        f = scan_snippet("a.js", "const h = crypto.createHash('md5');\nconst o = { rejectUnauthorized: false };\n")
        self.assertTrue({"SC007", "SC009"} <= rules(f))


class Secrets(unittest.TestCase):
    def test_evidence_is_redacted(self):
        f = scan_snippet("a.py", 'db_password = "Sup3rS3cretValue!"\n')
        self.assertTrue(f)
        self.assertNotIn("Sup3rS3cretValue", f[0].evidence)

    def test_placeholders_and_config_names_ignored(self):
        code = 'password = "changeme"\ntoken_url = "https://x.io/token"\npassword_field = "password"\nsecret = os.environ["S"]\n'
        self.assertEqual(scan_snippet("a.py", code), [])

    def test_known_token_format(self):
        f = scan_snippet("a.js", "const k = 'AKIAIOSFODNN7EXAMPLE';\n")
        self.assertIn("SC004", rules(f))


class EngineBehaviour(unittest.TestCase):
    def test_project_inside_excluded_folder_name_still_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            sub = Path(d) / "build" / "proj"
            sub.mkdir(parents=True)
            (sub / "a.py").write_text("import os\ndef f(x):\n    os.system('a' + x)\n")
            f, n, _ = Scanner({"build"}).scan(sub)
            self.assertEqual(n, 1)

    def test_exclude_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "node_modules").mkdir()
            (Path(d) / "node_modules" / "a.js").write_text("eval(x)\n")
            f, n, _ = Scanner({"node_modules"}).scan(Path(d))
            self.assertEqual(n, 0)

    def test_suppression_multiple_ids_and_previous_line(self):
        code = "import os\ndef f(x):\n    # sast:ignore SC002, SC001 -- reviewed\n    os.system('a' + x)\n"
        self.assertEqual(scan_snippet("a.py", code), [])

    def test_fingerprint_stable_when_lines_shift(self):
        a = scan_snippet("a.py", "import os\ndef f(x):\n    os.system('a' + x)\n")
        b = scan_snippet("a.py", "import os\n\n\n# c\ndef f(x):\n    os.system('a' + x)\n")
        self.assertEqual(a[0].fingerprint, b[0].fingerprint)
        self.assertNotEqual(a[0].line, b[0].line)

    def test_missing_target(self):
        with self.assertRaises(ValueError):
            Scanner().scan(Path("/definitely/not/here"))


class Reports(unittest.TestCase):
    def setUp(self):
        self.f, self.n, self.k = Scanner().scan(SAMPLES / "vulnerable")

    def test_json(self):
        data = json.loads(json_text(self.f, self.n, self.k))
        self.assertEqual(data["finding_count"], len(self.f))
        self.assertIn("fingerprint", data["findings"][0])

    def test_sarif_structure(self):
        s = sarif_dict(self.f, self.n, self.k)
        self.assertEqual(s["version"], "2.1.0")
        run = s["runs"][0]
        ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        for res in run["results"]:
            self.assertEqual(ids[res["ruleIndex"]], res["ruleId"])
            self.assertIn(res["level"], {"error", "warning", "note"})
            region = res["locations"][0]["physicalLocation"]["region"]
            self.assertGreaterEqual(region["startLine"], 1)
        json.dumps(s)


class CommandLine(unittest.TestCase):
    def run_cli(self, *args):
        import sast
        return sast.main(list(args))

    def test_exit_codes(self):
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.run_cli("scan", str(SAMPLES / "vulnerable")), 1)
            self.assertEqual(self.run_cli("scan", str(SAMPLES / "fixed")), 0)
            self.assertEqual(self.run_cli("scan", str(SAMPLES / "vulnerable"), "--exit-zero"), 0)
            self.assertEqual(self.run_cli("scan", str(SAMPLES / "vulnerable"), "--fail-on", "none"), 0)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_cli("scan", "/no/such/path"), 2)

    def test_baseline_roundtrip(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            base = str(Path(d) / "b.json")
            self.assertEqual(self.run_cli("scan", str(SAMPLES / "vulnerable"), "--write-baseline", base), 0)
            self.assertEqual(self.run_cli("scan", str(SAMPLES / "vulnerable"), "--baseline", base), 0)


if __name__ == "__main__":
    unittest.main()

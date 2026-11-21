import ast
import os
from typing import List, Dict, Any, Optional

class ASTFinding(BaseModel := object):
    pass

class PythonASTAnalyzer:
    def __init__(self, project_path: str):
        self.project_path = project_path

    def analyze_file(self, rel_path: str) -> List[Dict[str, Any]]:
        full_path = os.path.join(self.project_path, rel_path)
        if not os.path.exists(full_path):
            return []

        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            tree = ast.parse(code, filename=rel_path)
        except Exception:
            return []

        findings = []
        lines = code.splitlines()

        # 1. SQL Injection Detection via AST
        findings.extend(self._find_sql_injections(tree, rel_path, lines))

        # 2. Command Injection Detection via AST
        findings.extend(self._find_command_injections(tree, rel_path, lines))

        # 3. Insecure Deserialization via AST
        findings.extend(self._find_insecure_deserialization(tree, rel_path, lines))

        # 4. Broken Authorization on Sensitive Endpoints via AST
        findings.extend(self._find_broken_auth(tree, rel_path, lines))

        # 5. Dangerous Eval / Exec via AST
        findings.extend(self._find_dangerous_eval(tree, rel_path, lines))

        return findings

    def _get_snippet(self, lines: List[str], line_start: int, line_end: int) -> str:
        s = max(0, line_start - 1)
        e = min(len(lines), line_end)
        return "\n".join(lines[s:e])

    def _find_sql_injections(self, tree: ast.AST, rel_path: str, lines: List[str]) -> List[Dict[str, Any]]:
        findings = []

        # Track variable assignments of tainted/interpolated strings within functions
        for func_node in ast.walk(tree):
            if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                tainted_vars = {} # var_name -> (line, reason)

                for node in ast.walk(func_node):
                    # Check variable assignment
                    if isinstance(node, ast.Assign):
                        val = node.value
                        is_tainted = False
                        reason = ""
                        if isinstance(val, ast.JoinedStr):
                            is_tainted = True
                            reason = "SQL query constructed dynamically via f-string interpolation."
                        elif isinstance(val, ast.BinOp) and isinstance(val.op, (ast.Add, ast.Mod)):
                            is_tainted = True
                            reason = "SQL query constructed via string concatenation or '%' operator."
                        elif isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute) and val.func.attr == "format":
                            is_tainted = True
                            reason = "SQL query constructed using string .format() call."

                        if is_tainted:
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    tainted_vars[target.id] = (node.lineno, reason)

                    # Check execution sink
                    elif isinstance(node, ast.Call):
                        func_name = ""
                        if isinstance(node.func, ast.Attribute):
                            func_name = node.func.attr
                        elif isinstance(node.func, ast.Name):
                            func_name = node.func.id

                        if func_name in ("execute", "executemany", "raw") and node.args:
                            arg0 = node.args[0]
                            is_vulnerable = False
                            reason = ""
                            vuln_line = node.lineno

                            # Direct JoinedStr / BinOp
                            if isinstance(arg0, ast.JoinedStr):
                                is_vulnerable = True
                                reason = "SQL query constructed dynamically via f-string interpolation."
                            elif isinstance(arg0, ast.BinOp) and isinstance(arg0.op, (ast.Add, ast.Mod)):
                                is_vulnerable = True
                                reason = "SQL query constructed via string concatenation or '%' operator."
                            elif isinstance(arg0, ast.Call) and isinstance(arg0.func, ast.Attribute) and arg0.func.attr == "format":
                                is_vulnerable = True
                                reason = "SQL query constructed using string .format() call."
                            # Indirect variable reference (data-flow tracking)
                            elif isinstance(arg0, ast.Name) and arg0.id in tainted_vars:
                                is_vulnerable = True
                                def_line, r = tainted_vars[arg0.id]
                                reason = f"Variable '{arg0.id}' initialized dynamically via string formatting on line {def_line} executed in raw SQL sink."

                            if is_vulnerable:
                                start_l = vuln_line
                                end_l = getattr(node, "end_lineno", start_l)
                                findings.append({
                                    "title": "SQL Injection (CWE-89)",
                                    "cwe": "CWE-89",
                                    "severity": "CRITICAL",
                                    "confidence": 94,
                                    "exploitability": "HIGH",
                                    "category": "Injection",
                                    "file": rel_path,
                                    "line_start": start_l,
                                    "line_end": end_l,
                                    "code_snippet": self._get_snippet(lines, start_l, end_l),
                                    "source_scanner": "Python AST Analyzer",
                                    "reason": reason,
                                    "status": "CONFIRMED"
                                })
        return findings

    def _find_command_injections(self, tree: ast.AST, rel_path: str, lines: List[str]) -> List[Dict[str, Any]]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                module_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    if isinstance(node.func.value, ast.Name):
                        module_name = node.func.value.id
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                # subprocess with shell=True
                if module_name == "subprocess" or func_name in ("Popen", "call", "run", "check_output"):
                    has_shell_true = any(
                        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                        for kw in node.keywords
                    )
                    if has_shell_true:
                        start_l = node.lineno
                        end_l = getattr(node, "end_lineno", start_l)
                        findings.append({
                            "title": "OS Command Injection (CWE-78)",
                            "cwe": "CWE-78",
                            "severity": "CRITICAL",
                            "confidence": 95,
                            "exploitability": "HIGH",
                            "category": "Injection",
                            "file": rel_path,
                            "line_start": start_l,
                            "line_end": end_l,
                            "code_snippet": self._get_snippet(lines, start_l, end_l),
                            "source_scanner": "Python AST Analyzer",
                            "reason": "Subprocess execution invoked with shell=True allowing command injection.",
                            "status": "CONFIRMED"
                        })

                # os.system or os.popen
                if module_name == "os" and func_name in ("system", "popen"):
                    start_l = node.lineno
                    end_l = getattr(node, "end_lineno", start_l)
                    findings.append({
                        "title": "Dangerous Command Execution (CWE-78)",
                        "cwe": "CWE-78",
                        "severity": "HIGH",
                        "confidence": 90,
                        "exploitability": "HIGH",
                        "category": "Injection",
                        "file": rel_path,
                        "line_start": start_l,
                        "line_end": end_l,
                        "code_snippet": self._get_snippet(lines, start_l, end_l),
                        "source_scanner": "Python AST Analyzer",
                        "reason": f"Direct invocation of {module_name}.{func_name}() with shell command.",
                        "status": "CONFIRMED"
                    })
        return findings

    def _find_insecure_deserialization(self, tree: ast.AST, rel_path: str, lines: List[str]) -> List[Dict[str, Any]]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                module_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    if isinstance(node.func.value, ast.Name):
                        module_name = node.func.value.id

                # pickle.loads
                if module_name in ("pickle", "_pickle") and func_name in ("loads", "load"):
                    start_l = node.lineno
                    end_l = getattr(node, "end_lineno", start_l)
                    findings.append({
                        "title": "Insecure Deserialization (CWE-502)",
                        "cwe": "CWE-502",
                        "severity": "CRITICAL",
                        "confidence": 96,
                        "exploitability": "HIGH",
                        "category": "Deserialization",
                        "file": rel_path,
                        "line_start": start_l,
                        "line_end": end_l,
                        "code_snippet": self._get_snippet(lines, start_l, end_l),
                        "source_scanner": "Python AST Analyzer",
                        "reason": "Arbitrary code execution risk through untrusted pickle deserialization.",
                        "status": "CONFIRMED"
                    })

                # yaml.load without SafeLoader
                if module_name == "yaml" and func_name == "load":
                    has_safe_loader = any(
                        kw.arg == "Loader" and "Safe" in getattr(kw.value, "id", getattr(kw.value, "attr", ""))
                        for kw in node.keywords
                    )
                    if not has_safe_loader and len(node.args) < 2:
                        start_l = node.lineno
                        end_l = getattr(node, "end_lineno", start_l)
                        findings.append({
                            "title": "Unsafe YAML Deserialization (CWE-502)",
                            "cwe": "CWE-502",
                            "severity": "HIGH",
                            "confidence": 92,
                            "exploitability": "MEDIUM",
                            "category": "Deserialization",
                            "file": rel_path,
                            "line_start": start_l,
                            "line_end": end_l,
                            "code_snippet": self._get_snippet(lines, start_l, end_l),
                            "source_scanner": "Python AST Analyzer",
                            "reason": "yaml.load() called without yaml.SafeLoader enables arbitrary object instantiation.",
                            "status": "CONFIRMED"
                        })
        return findings

    def _find_broken_auth(self, tree: ast.AST, rel_path: str, lines: List[str]) -> List[Dict[str, Any]]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check if route decorator exists
                is_route = False
                is_sensitive_path = False
                route_path = ""

                for dec in node.decorator_list:
                    dec_str = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                    if any(r in dec_str for r in ("@app.", "@router.", "route(")):
                        is_route = True
                        if any(s in dec_str.lower() for s in ("/admin", "/delete", "/update", "/users", "/secret", "/settings", "/export")):
                            is_sensitive_path = True
                            route_path = dec_str

                if is_route and is_sensitive_path:
                    # Check if authentication decorator is present
                    has_auth_dec = False
                    for dec in node.decorator_list:
                        dec_str = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                        if any(a in dec_str.lower() for a in ("auth", "login", "jwt", "permission", "protect")):
                            has_auth_dec = True
                            break

                    if not has_auth_dec:
                        start_l = node.lineno
                        end_l = getattr(node, "end_lineno", start_l)
                        findings.append({
                            "title": "Missing Authorization on Sensitive Endpoint (CWE-306)",
                            "cwe": "CWE-306",
                            "severity": "HIGH",
                            "confidence": 88,
                            "exploitability": "HIGH",
                            "category": "Auth",
                            "file": rel_path,
                            "line_start": start_l,
                            "line_end": end_l,
                            "code_snippet": self._get_snippet(lines, start_l, min(lines.__len__(), start_l + 8)),
                            "source_scanner": "Python AST Analyzer",
                            "reason": f"Sensitive route endpoint '{node.name}' exposed without authorization checks or guard decorator.",
                            "status": "CONFIRMED"
                        })
        return findings

    def _find_dangerous_eval(self, tree: ast.AST, rel_path: str, lines: List[str]) -> List[Dict[str, Any]]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                if func_name in ("eval", "exec"):
                    start_l = node.lineno
                    end_l = getattr(node, "end_lineno", start_l)
                    findings.append({
                        "title": "Code Injection via Dangerous Evaluation (CWE-95)",
                        "cwe": "CWE-95",
                        "severity": "CRITICAL",
                        "confidence": 98,
                        "exploitability": "HIGH",
                        "category": "Injection",
                        "file": rel_path,
                        "line_start": start_l,
                        "line_end": end_l,
                        "code_snippet": self._get_snippet(lines, start_l, end_l),
                        "source_scanner": "Python AST Analyzer",
                        "reason": f"Use of dynamic evaluation function '{func_name}()' allows execution of arbitrary code.",
                        "status": "CONFIRMED"
                    })
        return findings

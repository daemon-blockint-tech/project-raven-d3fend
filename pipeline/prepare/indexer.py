"""
Language-aware indexer for the Prepare stage.
"""
import os
from typing import Dict, List, Any, Optional
import logging
from pathlib import Path
import ast
import json

logger = logging.getLogger(__name__)


class LanguageIndexer:
    """Build language-aware indices (AST, call graph, control flow)."""
    
    def __init__(self):
        """Initialize language indexer."""
        self.language_detectors = {
            ".py": self._detect_python,
            ".js": self._detect_javascript,
            ".ts": self._detect_typescript,
            ".rs": self._detect_rust,
            ".c": self._detect_c,
            ".cpp": self._detect_cpp,
            ".sol": self._detect_solidity,
        }
        logger.info("LanguageIndexer initialized")
    
    def build_index(self, repo_path: str) -> Dict[str, Any]:
        """
        Build language-aware index for a codebase.
        
        Args:
            repo_path: Path to codebase
            
        Returns:
            Dictionary with language index data
        """
        repo_path = Path(repo_path)
        
        # Detect languages
        languages = self._detect_languages(repo_path)
        
        # Build AST for supported languages
        ast_data = {}
        for lang, files in languages.items():
            if lang in ["python", "javascript", "typescript"]:
                ast_data[lang] = self._build_asts(files, lang)
        
        # Build call graph
        call_graph = self._build_call_graph(repo_path, languages)
        
        # Identify entry points
        entry_points = self._identify_entry_points(repo_path, languages)
        
        # Identify ABI boundaries (for smart contracts)
        abi_boundaries = []
        if "solidity" in languages:
            abi_boundaries = self._identify_solidity_abi(repo_path)
        
        return {
            "languages": languages,
            "ast_data": ast_data,
            "call_graph": call_graph,
            "entry_points": entry_points,
            "abi_boundaries": abi_boundaries
        }
    
    def _detect_languages(self, repo_path: Path) -> Dict[str, List[str]]:
        """Detect programming languages in codebase."""
        languages = {
            "python": [],
            "javascript": [],
            "typescript": [],
            "rust": [],
            "c": [],
            "cpp": [],
            "solidity": []
        }
        
        for root, dirs, files in os.walk(repo_path):
            # Skip hidden directories and common exclusions
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'venv', '__pycache__', 'target']]
            
            for file in files:
                file_path = Path(root) / file
                ext = file_path.suffix.lower()
                
                if ext in self.language_detectors:
                    lang_name = self._get_language_name(ext)
                    if lang_name:
                        languages[lang_name].append(str(file_path))
        
        # Filter empty language lists
        return {k: v for k, v in languages.items() if v}
    
    def _get_language_name(self, ext: str) -> Optional[str]:
        """Map file extension to language name."""
        mapping = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".rs": "rust",
            ".c": "c",
            ".cpp": "cpp",
            ".sol": "solidity"
        }
        return mapping.get(ext)
    
    def _detect_python(self, file_path: str) -> bool:
        """Detect if file is Python."""
        return file_path.endswith(".py")
    
    def _detect_javascript(self, file_path: str) -> bool:
        """Detect if file is JavaScript."""
        return file_path.endswith(".js")
    
    def _detect_typescript(self, file_path: str) -> bool:
        """Detect if file is TypeScript."""
        return file_path.endswith(".ts")
    
    def _detect_rust(self, file_path: str) -> bool:
        """Detect if file is Rust."""
        return file_path.endswith(".rs")
    
    def _detect_c(self, file_path: str) -> bool:
        """Detect if file is C."""
        return file_path.endswith(".c")
    
    def _detect_cpp(self, file_path: str) -> bool:
        """Detect if file is C++."""
        return file_path.endswith(".cpp") or file_path.endswith(".cc") or file_path.endswith(".cxx")
    
    def _detect_solidity(self, file_path: str) -> bool:
        """Detect if file is Solidity."""
        return file_path.endswith(".sol")
    
    def _build_asts(self, files: List[str], language: str = "python") -> Dict[str, Any]:
        """Build ASTs for files. Uses Python ast for .py, regex-based extraction for JS/TS."""
        asts = {}
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    source = f.read()
                
                if language == "python":
                    tree = ast.parse(source)
                    asts[file_path] = {
                        "functions": self._extract_functions(tree),
                        "classes": self._extract_classes(tree),
                        "imports": self._extract_imports(tree)
                    }
                elif language in ("javascript", "typescript"):
                    asts[file_path] = self._extract_js_ts_symbols(source, file_path)
            except SyntaxError as e:
                logger.warning(f"Syntax error parsing {file_path}: {e}")
            except Exception as e:
                logger.warning(f"Failed to parse AST for {file_path}: {e}")
        
        return asts
    
    def _extract_js_ts_symbols(self, source: str, file_path: str) -> Dict[str, Any]:
        """Extract functions, classes, and imports from JS/TS using regex."""
        import re
        
        functions = []
        classes = []
        imports = []
        
        # Extract imports
        for match in re.finditer(r'^(?:import\s+.*?from\s+[\'"]([^\'"]+)[\'"]|import\s+[\'"]([^\'"]+)[\'"])', source, re.MULTILINE):
            imports.append(match.group(1) or match.group(2))
        
        # Extract function declarations (named, arrow, async)
        for match in re.finditer(r'(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)', source):
            params = [p.strip().split(':')[0].split('=')[0].strip() for p in match.group(2).split(',') if p.strip()]
            functions.append({
                "name": match.group(1),
                "params": params,
                "async": "async" in match.group(0),
                "export": "export" in match.group(0)
            })
        
        # Extract arrow functions assigned to variables
        for match in re.finditer(r'(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>', source):
            params = [p.strip().split(':')[0].split('=')[0].strip() for p in match.group(2).split(',') if p.strip()]
            functions.append({
                "name": match.group(1),
                "params": params,
                "type": "arrow",
                "async": "async" in match.group(0),
                "export": "export" in match.group(0)
            })
        
        # Extract class declarations
        for match in re.finditer(r'(?:export\s+)?(?:abstract\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([\w,\s]+))?', source):
            classes.append({
                "name": match.group(1),
                "extends": match.group(2),
                "implements": [i.strip() for i in match.group(3).split(',')] if match.group(3) else [],
                "export": "export" in match.group(0)
            })
        
        return {
            "functions": functions,
            "classes": classes,
            "imports": imports
        }
    
    def _extract_functions(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract function definitions from AST."""
        functions = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.append({
                    "name": node.name,
                    "lineno": node.lineno,
                    "args": [arg.arg for arg in node.args.args],
                    "decorators": [self._get_decorator_name(d) for d in node.decorator_list]
                })
        
        return functions
    
    def _extract_classes(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract class definitions from AST."""
        classes = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes.append({
                    "name": node.name,
                    "lineno": node.lineno,
                    "bases": [self._get_name(base) for base in node.bases],
                    "methods": [n.name for n in node.body if isinstance(n, ast.FunctionDef)]
                })
        
        return classes
    
    def _extract_imports(self, tree: ast.AST) -> List[str]:
        """Extract import statements from AST."""
        imports = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module if node.module else ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}")
        
        return imports
    
    def _get_decorator_name(self, decorator: ast.expr) -> str:
        """Get decorator name."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Call):
            return self._get_name(decorator.func)
        return ""
    
    def _get_name(self, node: ast.expr) -> str:
        """Get name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_name(node.value)}.{node.attr}"
        return ""
    
    def _build_call_graph(self, repo_path: Path, languages: Dict[str, List[str]]) -> Dict[str, Any]:
        """Build call graph from AST data."""
        # Simplified call graph - in production, use more sophisticated analysis
        call_graph = {}
        
        if "python" in languages:
            for file_path in languages["python"]:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        source = f.read()
                    
                    tree = ast.parse(source)
                    functions = self._extract_functions(tree)
                    
                    for func in functions:
                        calls = self._extract_function_calls(tree, func["lineno"])
                        call_graph[f"{file_path}:{func['name']}"] = {
                            "file": file_path,
                            "function": func["name"],
                            "calls": calls
                        }
                except Exception as e:
                    logger.warning(f"Failed to build call graph for {file_path}: {e}")
        
        return call_graph
    
    def _extract_function_calls(self, tree: ast.AST, lineno: int) -> List[str]:
        """Extract function calls from a function."""
        calls = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if hasattr(node, 'lineno') and node.lineno >= lineno:
                    call_name = self._get_name(node.func)
                    if call_name:
                        calls.append(call_name)
        
        return calls
    
    def _identify_entry_points(self, repo_path: Path, languages: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Identify potential entry points in the codebase."""
        entry_points = []
        
        # Common entry point patterns
        entry_point_patterns = {
            "python": ["main(", "if __name__ == '__main__'", "app.run(", "Flask(", "FastAPI("],
            "javascript": ["app.listen(", "express(", "server.listen(", "createServer("],
            "typescript": ["app.listen(", "express(", "server.listen(", "createServer(", "Bun.serve(", "new Hono("],
            "rust": ["fn main(", "#[main]"],
            "solidity": ["function ", "constructor("]
        }
        
        for lang, files in languages.items():
            patterns = entry_point_patterns.get(lang, [])
            
            for file_path in files:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        source = f.read()
                    
                    for pattern in patterns:
                        if pattern in source:
                            entry_points.append({
                                "file": file_path,
                                "language": lang,
                                "pattern": pattern
                            })
                            break
                except Exception as e:
                    logger.warning(f"Failed to scan {file_path} for entry points: {e}")
        
        return entry_points
    
    def _identify_solidity_abi(self, repo_path: Path) -> List[Dict[str, Any]]:
        """Identify ABI boundaries in Solidity contracts."""
        abi_boundaries = []
        
        if "solidity" not in self.language_detectors:
            return abi_boundaries
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                if file.endswith(".sol"):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            source = f.read()
                        
                        # Extract public/external functions (ABI boundaries)
                        lines = source.split('\n')
                        for i, line in enumerate(lines, 1):
                            line = line.strip()
                            if line.startswith("function ") or line.startswith("external "):
                                abi_boundaries.append({
                                    "file": str(file_path),
                                    "line": i,
                                    "signature": line
                                })
                    except Exception as e:
                        logger.warning(f"Failed to analyze Solidity ABI in {file_path}: {e}")
        
        return abi_boundaries

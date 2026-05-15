"""
Cross-Language Security Analysis Layer

Provides security analysis for cross-language and cross-runtime boundaries,
including FFI boundaries, Solidity smart contracts, WASM runtimes, and taint tracking.
"""

from .ffi_analyzer import FFIBoundaryAnalyzer
from .solidity_analyzer import SolidityNativeAnalyzer
from .wasm_analyzer import WASMRuntimeAnalyzer
from .taint_tracker import CrossLanguageTaintTracker, TaintAnalysisResult, TaintFlow, TaintSource, TaintSink

__all__ = [
    'FFIBoundaryAnalyzer',
    'SolidityNativeAnalyzer',
    'WASMRuntimeAnalyzer',
    'CrossLanguageTaintTracker',
    'TaintAnalysisResult',
    'TaintFlow',
    'TaintSource',
    'TaintSink',
]

"""
Specialized auditor agent using the OpenAI Agents SDK.

Maps MDASH bug-class auditor agents to OpenAI Agents SDK Agent definitions
with instructions, tools, and guardrails.
"""
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Try importing openai-agents SDK
try:
    from agents import Agent, Runner
    from agents.run import RunConfig
    from agents.tool import function_tool
    OPENAI_AGENTS_AVAILABLE = True
except ImportError:
    OPENAI_AGENTS_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class AuditorConfig:
    """Configuration for a specialized auditor agent."""
    name: str
    bug_class: str
    instructions: str
    model: str = "gpt-4o"
    temperature: float = 0.0
    tools: List[Any] = None


class AuditorAgent:
    """
    A specialized bug-class auditor agent backed by the OpenAI Agents SDK.

    Each auditor focuses on one bug class (memory-corruption, race-condition,
    auth-bypass, etc.) and uses domain-specific tools and instructions.
    """

    # Domain-specific instructions per bug class
    INSTRUCTIONS = {
        "memory-corruption": """You are a specialized memory corruption auditor.
Your task is to analyze code for buffer overflows, use-after-free, double-free,
and other memory safety violations.

Instructions:
1. Examine the provided code for unsafe memory operations
2. Track object lifetimes across function boundaries
3. Identify missing bounds checks or incorrect size calculations
4. Report findings with file, line, and a CWE mapping
5. If no vulnerability is found, explicitly state "no issues found"

Rules:
- Do not report theoretical issues without a concrete code path
- Prioritize remotely/externally reachable paths
- Reference specific line numbers and variable names
""",
        "race-condition": """You are a specialized concurrency auditor.
Your task is to find race conditions, missing locks, TOCTOU bugs, and
synchronization errors.

Instructions:
1. Identify shared mutable state accessed by multiple threads
2. Check for proper lock ordering and lock hierarchy
3. Look for double-fetch patterns (TOCTOU)
4. Verify atomic operations on shared counters
5. Report findings with the competing access paths

Rules:
- Distinguish between benign data races and exploitable races
- Consider kernel IRQL/interrupt context when relevant
- Reference specific lock objects and their scopes
""",
        "auth-bypass": """You are a specialized authentication/authorization auditor.
Your task is to find auth bypasses, privilege escalation paths, and
incorrect access control checks.

Instructions:
1. Trace authentication checks from entry points to sensitive operations
2. Identify missing or incorrectly ordered authorization checks
3. Look for hardcoded credentials, tokens, or certificates
4. Check for path traversal or symlink attacks
5. Verify that all admin paths require proper elevation

Rules:
- Focus on externally reachable entry points
- Distinguish between design flaws and implementation bugs
- Reference specific functions and their privilege requirements
""",
        "integer-overflow": """You are a specialized integer arithmetic auditor.
Your task is to find integer overflows, underflows, and incorrect type
conversions that lead to security issues.

Instructions:
1. Identify arithmetic operations on attacker-controlled values
2. Check for missing overflow checks before allocation size calculations
3. Look for signed/unsigned confusion in comparisons
4. Verify loop bounds and array index calculations
5. Report findings with the specific operation and its inputs

Rules:
- Focus on operations that feed into memory allocation or buffer sizing
- Consider implicit casts and promotion rules
- Reference specific variables and their types
""",
        "default": """You are a security code auditor.
Your task is to analyze code for security vulnerabilities.

Instructions:
1. Examine the code for common vulnerability patterns
2. Trace attacker-controlled input through the code
3. Identify missing validation or incorrect error handling
4. Report findings with file, line, and CWE mapping
5. If no vulnerability is found, explicitly state "no issues found"

Rules:
- Do not report theoretical issues without a concrete code path
- Focus on externally reachable entry points
- Be specific about locations and conditions
"""
    }

    def __init__(
        self,
        bug_class: str,
        model: str = "gpt-4o",
        temperature: float = 0.0,
        custom_tools: Optional[List[Any]] = None
    ):
        """
        Initialize an auditor agent for a specific bug class.

        Args:
            bug_class: The bug class this agent specializes in
            model: LLM model to use
            temperature: Sampling temperature (0 for deterministic audits)
            custom_tools: Additional tools for this agent
        """
        if not OPENAI_AGENTS_AVAILABLE:
            raise ImportError(
                "openai-agents package not installed. "
                "Install with: pip install openai-agents"
            )

        self.bug_class = bug_class
        self.model = model
        self.temperature = temperature
        self.tools = custom_tools or []

        # Build the OpenAI Agent
        instructions = self.INSTRUCTIONS.get(bug_class, self.INSTRUCTIONS["default"])

        self.agent = Agent(
            name=f"auditor-{bug_class}",
            instructions=instructions,
            model=model,
            tools=self.tools,
        )

        logger.info("AuditorAgent '%s' initialized with model %s", bug_class, model)

    def audit(
        self,
        code_snippet: str,
        file_path: str,
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run the auditor agent against a code snippet.

        Args:
            code_snippet: The code to analyze
            file_path: Path to the source file
            context: Additional context (callers, data flow, etc.)

        Returns:
            Dict with findings or empty list if none found
        """
        # Build the audit prompt
        prompt = self._build_audit_prompt(code_snippet, file_path, context)

        # Run the agent
        result = Runner.run_sync(
            self.agent,
            prompt,
            run_config=RunConfig(
                temperature=self.temperature,
                # Enable tracing for debugging
                tracing=True,
            )
        )

        # Parse the result
        return self._parse_audit_result(result)

    def _build_audit_prompt(
        self,
        code_snippet: str,
        file_path: str,
        context: Optional[str] = None
    ) -> str:
        """Build the prompt for the auditor agent."""
        prompt = f"""Analyze the following code for {self.bug_class} vulnerabilities.

File: {file_path}

```c
{code_snippet}
```
"""
        if context:
            prompt += f"""
Additional context:
{context}
"""

        prompt += """
Report your findings in this format:
- ISSUE: <yes/no>
- LOCATION: <file:line or function>
- DESCRIPTION: <one-line description>
- CWE: <CWE-ID or N/A>
- CONFIDENCE: <high/medium/low>
- ATTACKER_CONTROL: <what input the attacker controls>
"""
        return prompt

    def _parse_audit_result(self, result: Any) -> Dict[str, Any]:
        """Parse the agent's output into structured findings."""
        output = result.final_output

        # Simple parsing - in production this would be more robust
        findings = []
        if "ISSUE: yes" in output.lower() or "yes" in output.lower():
            # Extract structured data from the output
            finding = {
                "bug_class": self.bug_class,
                "raw_output": output,
                "agent_name": self.agent.name,
                "model": self.model,
            }
            findings.append(finding)

        return {
            "findings": findings,
            "raw_output": output,
            "agent_name": self.agent.name,
        }

"""
Debater agent using the OpenAI Agents SDK.

Maps MDASH multi-model debate to OpenAI Agents SDK with structured
personas and voting.
"""
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

# Try importing openai-agents SDK
try:
    from agents import Agent, Runner
    from agents.run import RunConfig
    OPENAI_AGENTS_AVAILABLE = True
except ImportError:
    OPENAI_AGENTS_AVAILABLE = False

logger = logging.getLogger(__name__)


class DebateStance(Enum):
    """Possible stances in a debate."""
    FOR = "for"
    AGAINST = "against"
    NEUTRAL = "neutral"


@dataclass
class DebateVote:
    """A single debater's vote on a candidate finding."""
    agent_name: str
    model: str
    stance: DebateStance
    confidence: float
    reasoning: str


class DebaterAgent:
    """
    A debate agent that argues for or against a candidate finding.

    Debater agents use different models/personas to reduce correlated
    errors and surface diverse perspectives.
    """

    PERSONAS = {
        DebateStance.FOR: """You are a security researcher arguing that the presented
candidate finding is a genuine, exploitable vulnerability.

Your job:
1. Construct the strongest possible case that the bug is real
2. Trace the attacker-controlled input to the vulnerable sink
3. Explain how the bug could be triggered in practice
4. Cite specific code lines and variables that support your argument
5. Address potential counter-arguments proactively

Rules:
- Be specific, not vague. Cite line numbers and variable names.
- Do not invent code that does not exist in the snippet.
- If the evidence is weak, say so honestly rather than overstating.
""",
        DebateStance.AGAINST: """You are a skeptical security researcher arguing that
the presented candidate finding is NOT a genuine vulnerability.

Your job:
1. Find the strongest reason the bug might be a false positive
2. Check for missing preconditions (is the attacker input actually reachable?)
3. Look for guard checks, sanitization, or implicit protections
4. Verify that the claimed sink is actually reachable from the entry point
5. Cite specific code lines that contradict the finding

Rules:
- Be specific, not vague. Cite line numbers and variable names.
- Do not dismiss findings out of hand — engage with the evidence.
- If the finding is correct, concede that rather than arguing in bad faith.
""",
        DebateStance.NEUTRAL: """You are an impartial judge evaluating a debated
security finding.

Your job:
1. Summarize the arguments for and against
2. Identify which evidence is strongest on each side
3. Point out any logical gaps or unsupported claims
4. Give a clear verdict: is the finding valid, invalid, or indeterminate?
5. State your confidence level and what additional evidence would help

Rules:
- Do not favor one side by default — evaluate purely on evidence quality.
- If both sides have merit, say so and explain what would break the tie.
"""
    }

    def __init__(
        self,
        stance: DebateStance,
        model: str = "gpt-4o",
        temperature: float = 0.0
    ):
        """
        Initialize a debater agent.

        Args:
            stance: Whether this agent argues for, against, or judges
            model: LLM model to use
            temperature: Sampling temperature
        """
        if not OPENAI_AGENTS_AVAILABLE:
            raise ImportError(
                "openai-agents package not installed. "
                "Install with: pip install openai-agents"
            )

        self.stance = stance
        self.model = model
        self.temperature = temperature

        # Build the OpenAI Agent
        persona = self.PERSONAS.get(stance, self.PERSONAS[DebateStance.NEUTRAL])

        self.agent = Agent(
            name=f"debater-{stance.value}",
            instructions=persona,
            model=model,
        )

        logger.info("DebaterAgent '%s' initialized with model %s", stance.value, model)

    def debate(
        self,
        candidate_finding: Dict[str, Any],
        code_context: str,
        opposing_arguments: Optional[List[str]] = None
    ) -> DebateVote:
        """
        Run the debater agent on a candidate finding.

        Args:
            candidate_finding: The finding being debated
            code_context: Surrounding code for context
            opposing_arguments: Previous arguments from other debaters

        Returns:
            DebateVote with stance, confidence, and reasoning
        """
        prompt = self._build_debate_prompt(candidate_finding, code_context, opposing_arguments)

        result = Runner.run_sync(
            self.agent,
            prompt,
            run_config=RunConfig(
                temperature=self.temperature,
                tracing=True,
            )
        )

        return self._parse_debate_result(result)

    def _build_debate_prompt(
        self,
        finding: Dict[str, Any],
        code_context: str,
        opposing: Optional[List[str]] = None
    ) -> str:
        """Build the debate prompt."""
        prompt = f"""Candidate Finding:
- Bug class: {finding.get('bug_class', 'unknown')}
- Location: {finding.get('location', 'unknown')}
- Description: {finding.get('description', 'unknown')}
- CWE: {finding.get('cwe_id', 'N/A')}

Code context:
```c
{code_context}
```
"""
        if opposing:
            prompt += """
Previous arguments from other debaters:
"""
            for i, arg in enumerate(opposing, 1):
                prompt += f"\n--- Argument {i} ---\n{arg}\n"

        prompt += """
Present your argument. Then conclude with:
- STANCE: <for/against/neutral>
- CONFIDENCE: <0.0-1.0>
- REASONING: <one-paragraph summary>
"""
        return prompt

    def _parse_debate_result(self, result: Any) -> DebateVote:
        """Parse the debate output into a structured vote."""
        output = result.final_output

        # Extract stance
        stance = self.stance
        if "STANCE:" in output:
            stance_str = output.split("STANCE:")[1].split("\n")[0].strip().lower()
            if "for" in stance_str or "confirm" in stance_str:
                stance = DebateStance.FOR
            elif "against" in stance_str or "reject" in stance_str:
                stance = DebateStance.AGAINST
            else:
                stance = DebateStance.NEUTRAL

        # Extract confidence
        confidence = 0.5
        if "CONFIDENCE:" in output:
            try:
                conf_str = output.split("CONFIDENCE:")[1].split("\n")[0].strip()
                confidence = float(conf_str)
            except (ValueError, IndexError):
                pass

        # Extract reasoning
        reasoning = output
        if "REASONING:" in output:
            reasoning = output.split("REASONING:")[1].strip()

        return DebateVote(
            agent_name=self.agent.name,
            model=self.model,
            stance=stance,
            confidence=confidence,
            reasoning=reasoning
        )


class DebateOrchestrator:
    """
    Orchestrate multi-model debate using the OpenAI Agents SDK.

    Creates a panel of debaters with different models/stances and
    aggregates their votes into a final validation decision.
    """

    def __init__(
        self,
        debater_models: List[str] = None,
        vote_threshold: float = 0.67
    ):
        """
        Initialize the debate orchestrator.

        Args:
            debater_models: List of models to use for debaters (diverse = better)
            vote_threshold: Fraction of votes needed to confirm a finding
        """
        if not OPENAI_AGENTS_AVAILABLE:
            raise ImportError(
                "openai-agents package not installed. "
                "Install with: pip install openai-agents"
            )

        self.debater_models = debater_models or [
            "gpt-4o",
            "gpt-4o-mini",
            "claude-3-5-sonnet-20241022",
        ]
        self.vote_threshold = vote_threshold
        self.debaters: List[DebaterAgent] = []

    def create_panel(self, finding: Dict[str, Any]) -> List[DebaterAgent]:
        """Create a debate panel for a specific finding."""
        panel = []

        # Create debaters with different models and stances
        for i, model in enumerate(self.debater_models):
            if i % 2 == 0:
                stance = DebateStance.FOR
            else:
                stance = DebateStance.AGAINST

            debater = DebaterAgent(stance=stance, model=model)
            panel.append(debater)

        # Add a neutral judge
        judge = DebaterAgent(stance=DebateStance.NEUTRAL, model="gpt-4o")
        panel.append(judge)

        return panel

    def run_debate(
        self,
        finding: Dict[str, Any],
        code_context: str
    ) -> Dict[str, Any]:
        """
        Run full debate on a candidate finding.

        Args:
            finding: The candidate finding to validate
            code_context: Surrounding code

        Returns:
            Dict with validation result, vote tally, and transcript
        """
        panel = self.create_panel(finding)
        votes: List[DebateVote] = []
        arguments: List[str] = []

        # First round: for/against agents present their cases
        for debater in panel:
            if debater.stance != DebateStance.NEUTRAL:
                vote = debater.debate(finding, code_context, arguments)
                votes.append(vote)
                arguments.append(vote.reasoning)

        # Second round: judge evaluates all arguments
        judge = panel[-1]  # Last debater is the judge
        verdict = judge.debate(finding, code_context, arguments)

        # Tally votes
        for_votes = sum(1 for v in votes if v.stance == DebateStance.FOR)
        against_votes = sum(1 for v in votes if v.stance == DebateStance.AGAINST)
        total = len([v for v in votes if v.stance != DebateStance.NEUTRAL])

        confidence = sum(v.confidence for v in votes) / len(votes) if votes else 0.0

        validated = False
        if total > 0:
            for_ratio = for_votes / total
            validated = for_ratio >= self.vote_threshold and verdict.stance == DebateStance.FOR

        return {
            "validated": validated,
            "for_votes": for_votes,
            "against_votes": against_votes,
            "total_votes": total,
            "confidence": confidence,
            "judge_verdict": verdict.stance.value,
            "judge_confidence": verdict.confidence,
            "transcript": [v.__dict__ for v in votes + [verdict]],
        }

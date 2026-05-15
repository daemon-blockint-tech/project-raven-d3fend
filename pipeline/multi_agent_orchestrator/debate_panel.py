"""
Multi-Model Debate Panel for the Validate Stage.

Orchestrates 3-7 debater agents per finding, aggregates votes,
and produces a validation decision with confidence scoring.
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from .agent_core import Agent
from .model_router import ModelRouter
from .config import DEBATER_AGENTS, AgentDefinition

logger = logging.getLogger(__name__)


@dataclass
class DebateVote:
    agent_id: str
    agent_name: str
    model: str
    vote: str  # 'FOR' | 'AGAINST' | 'ABSTAIN'
    confidence: float  # 0.0 - 1.0
    reasoning: str = ""


@dataclass
class DebateResult:
    finding_id: str
    votes: List[DebateVote]
    for_count: int = 0
    against_count: int = 0
    abstain_count: int = 0
    confidence: float = 0.0
    validated: bool = False
    transcript: str = ""

    def __post_init__(self):
        self.for_count = sum(1 for v in self.votes if v.vote == "FOR")
        self.against_count = sum(1 for v in self.votes if v.vote == "AGAINST")
        self.abstain_count = sum(1 for v in self.votes if v.vote == "ABSTAIN")


class DebatePanel:
    """
    Multi-model debate panel for validating findings.

    Configurable panel size (3-7 debaters). Each debater gets the same
    finding and code context, but uses a different model/persona.
    """

    def __init__(
        self,
        model_router: ModelRouter,
        panel_size: int = 3,
        vote_threshold: float = 0.67,
    ):
        self.model_router = model_router
        self.panel_size = min(max(panel_size, 3), 7)
        self.vote_threshold = vote_threshold
        self.debaters: Dict[str, Agent] = {}

        logger.info(f"DebatePanel initialized (panel_size={panel_size}, threshold={vote_threshold})")

    async def create_panel(self):
        """Create the debate panel by spawning debater agents."""
        debater_defs = list(DEBATER_AGENTS.values())[:self.panel_size]

        for defn in debater_defs:
            model = self.model_router.select_model(
                task_complexity=defn.complexity,
                preferred_model=defn.model_preference,
            )
            agent = Agent(
                agent_id=defn.agent_id,
                name=defn.name,
                instructions=defn.instructions,
                model=model,
                max_steps=defn.max_steps,
            )
            self.debaters[defn.agent_id] = agent
            logger.debug(f"Debate panel added {defn.agent_id} ({model})")

    async def run_debate(
        self,
        finding: Dict[str, Any],
        code_context: str = "",
    ) -> DebateResult:
        """
        Run a debate on a single finding.

        Args:
            finding: The candidate finding to validate
            code_context: Surrounding code context

        Returns:
            DebateResult with votes and validation decision
        """
        if not self.debaters:
            await self.create_panel()

        # Build debate prompt
        prompt = self._build_debate_prompt(finding, code_context)

        # Run all debaters in parallel
        tasks = [
            self._run_debater(agent_id, agent, prompt)
            for agent_id, agent in self.debaters.items()
        ]
        votes = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out errors
        valid_votes = [v for v in votes if isinstance(v, DebateVote)]
        errors = [v for v in votes if isinstance(v, Exception)]
        for e in errors:
            logger.error(f"Debater error: {e}")

        # Aggregate results
        result = DebateResult(
            finding_id=finding.get("id", "unknown"),
            votes=valid_votes,
        )

        # Determine validation
        total_votes = result.for_count + result.against_count
        if total_votes > 0:
            result.confidence = result.for_count / total_votes
            result.validated = result.confidence >= self.vote_threshold

        # Build transcript
        result.transcript = self._build_transcript(result)

        logger.info(
            f"Debate for {result.finding_id}: "
            f"FOR={result.for_count}, AGAINST={result.against_count}, "
            f"confidence={result.confidence:.2f}, validated={result.validated}"
        )

        return result

    async def _run_debater(
        self,
        agent_id: str,
        agent: Agent,
        prompt: str,
    ) -> DebateVote:
        """Run a single debater and parse their vote."""
        try:
            response = await agent.run(prompt)
            vote, confidence, reasoning = self._parse_vote(response)

            return DebateVote(
                agent_id=agent_id,
                agent_name=agent.name,
                model=agent.model,
                vote=vote,
                confidence=confidence,
                reasoning=reasoning,
            )
        except Exception as e:
            logger.error(f"Debater {agent_id} failed: {e}")
            return DebateVote(
                agent_id=agent_id,
                agent_name=agent.name,
                model=agent.model,
                vote="ABSTAIN",
                confidence=0.0,
                reasoning=f"Error: {e}",
            )

    def _build_debate_prompt(
        self,
        finding: Dict[str, Any],
        code_context: str,
    ) -> str:
        return f"""## DEBATE PROMPT

### Candidate Finding
- ID: {finding.get('id', 'N/A')}
- Bug Class: {finding.get('bug_class', 'N/A')}
- Location: {finding.get('location', 'N/A')}
- Severity: {finding.get('severity', 'N/A')}
- Description: {finding.get('description', 'N/A')}

### Code Context
```
{code_context[:2000]}
```

### Instructions
Analyze this finding and cast your vote:
- FOR: The vulnerability is real and exploitable
- AGAINST: The vulnerability is a false positive or not exploitable
- ABSTAIN: Insufficient information to decide

Provide your reasoning and a confidence score (0.0-1.0).
Format your response as:
VOTE: <FOR|AGAINST|ABSTAIN>
CONFIDENCE: <0.0-1.0>
REASONING: <your detailed reasoning>
"""

    def _parse_vote(self, response: str) -> tuple:
        """Parse vote, confidence, and reasoning from debater response."""
        vote = "ABSTAIN"
        confidence = 0.5
        reasoning = response

        # Simple parsing
        lines = response.split("\n")
        for line in lines:
            line = line.strip()
            if line.startswith("VOTE:"):
                v = line.split(":", 1)[1].strip().upper()
                if v in ("FOR", "AGAINST", "ABSTAIN"):
                    vote = v
            elif line.startswith("CONFIDENCE:"):
                try:
                    c = float(line.split(":", 1)[1].strip())
                    confidence = max(0.0, min(1.0, c))
                except ValueError:
                    pass
            elif line.startswith("REASONING:"):
                reasoning = line.split(":", 1)[1].strip()

        return vote, confidence, reasoning

    def _build_transcript(self, result: DebateResult) -> str:
        lines = [f"# Debate Transcript: {result.finding_id}", ""]
        lines.append(f"Result: {'VALIDATED' if result.validated else 'REJECTED'}")
        lines.append(f"Confidence: {result.confidence:.2f}")
        lines.append("")

        for v in result.votes:
            lines.append(f"## {v.agent_name} ({v.model})")
            lines.append(f"Vote: {v.vote} (confidence: {v.confidence:.2f})")
            lines.append(f"Reasoning: {v.reasoning}")
            lines.append("")

        return "\n".join(lines)

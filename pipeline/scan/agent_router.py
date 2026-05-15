"""
Agent router for the Scan stage - routes to specialized auditor agents.
"""
from typing import Dict, List, Any, Optional
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openrouter_integration.client import OpenRouterClient
from openrouter_integration.model_selector import ModelSelector
from openrouter_integration.cost_tracker import CostTracker
from ..models import ThreatModel, SurfaceMap, CandidateFinding, BugClass

logger = logging.getLogger(__name__)


class AgentRouter:
    """Route code analysis to specialized auditor agents based on bug class."""
    
    def __init__(
        self,
        openrouter_client: OpenRouterClient,
        model_selector: ModelSelector,
        cost_tracker: CostTracker,
        config: Dict[str, Any]
    ):
        """
        Initialize agent router.
        
        Args:
            openrouter_client: OpenRouter client instance
            model_selector: Model selector instance
            cost_tracker: Cost tracker instance
            config: Configuration dictionary
        """
        self.client = openrouter_client
        self.model_selector = model_selector
        self.cost_tracker = cost_tracker
        self.config = config
        self.agent_routing = config.get("agent_routing", {})
        self.agents_per_function = config.get("agents_per_function", 5)
        self.temperature = config.get("temperature", 0.3)
        self.max_tokens = config.get("max_tokens", 8192)
        logger.info("AgentRouter initialized")
    
    def route_and_scan(
        self,
        threat_model: ThreatModel,
        surface_map: SurfaceMap,
        language_index: Dict[str, Any]
    ) -> List[CandidateFinding]:
        """
        Route code to specialized agents and collect findings.
        
        Args:
            threat_model: Threat model from Prepare stage
            surface_map: Surface map from Prepare stage
            language_index: Language index data
            
        Returns:
            List of candidate findings
        """
        findings = []
        
        # Get high-risk areas from threat model
        high_risk_areas = threat_model.high_risk_areas
        
        if not high_risk_areas:
            logger.warning("No high-risk areas identified in threat model")
            return findings
        
        # For each high-risk area, determine bug class and route to appropriate agent
        for area in high_risk_areas:
            location = area.get("location", "")
            risk_type = area.get("risk_type", "")
            
            # Determine bug class based on risk type
            bug_class = self._determine_bug_class(risk_type, language_index)
            
            # Select model for this bug class
            model = self.model_selector.select_for_bug_class(
                bug_class.value,
                language=self._detect_primary_language(language_index)
            )
            
            # Run specialized agent
            agent_findings = self._run_specialized_agent(
                bug_class=bug_class,
                location=location,
                model=model,
                context=self._build_agent_context(
                    area, surface_map, language_index
                )
            )
            
            findings.extend(agent_findings)
        
        # Also scan threat hypotheses
        for hypothesis in threat_model.threat_hypotheses:
            location = hypothesis.get("location", "")
            threat_type = hypothesis.get("threat_type", "")
            
            bug_class = self._map_threat_to_bug_class(threat_type)
            model = self.model_selector.select_for_bug_class(bug_class.value)
            
            agent_findings = self._run_specialized_agent(
                bug_class=bug_class,
                location=location,
                model=model,
                context=self._build_agent_context_from_hypothesis(
                    hypothesis, surface_map, language_index
                )
            )
            
            findings.extend(agent_findings)
        
        logger.info(f"Scan stage completed with {len(findings)} candidate findings")
        return findings
    
    def _determine_bug_class(self, risk_type: str, language_index: Dict[str, Any]) -> BugClass:
        """Determine bug class based on risk type."""
        risk_mapping = {
            "data_handling": BugClass.MEMORY_CORRUPTION,
            "input_validation": BugClass.INTEGER_OVERFLOW,
            "concurrency": BugClass.RACE_CONDITION,
            "authentication": BugClass.AUTH_BYPASS,
            "serialization": BugClass.DESERIALIZATION,
            "type_safety": BugClass.TYPE_CONFUSION,
            "signature": BugClass.SIGNATURE_MALLEABILITY,
            "account": BugClass.ACCOUNT_CONFUSION,
            "oracle": BugClass.ORACLE_MANIPULATION
        }
        
        return risk_mapping.get(risk_type, BugClass.LOGIC_ERROR)
    
    def _map_threat_to_bug_class(self, threat_type: str) -> BugClass:
        """Map threat type to bug class."""
        threat_mapping = {
            "buffer_overflow": BugClass.MEMORY_CORRUPTION,
            "integer_overflow": BugClass.INTEGER_OVERFLOW,
            "race_condition": BugClass.RACE_CONDITION,
            "auth_bypass": BugClass.AUTH_BYPASS,
            "injection": BugClass.DESERIALIZATION,
            "type_confusion": BugClass.TYPE_CONFUSION,
            "reentrancy": BugClass.REENTRANCY,
            "logic": BugClass.LOGIC_ERROR
        }
        
        return threat_mapping.get(threat_type.lower(), BugClass.LOGIC_ERROR)
    
    def _detect_primary_language(self, language_index: Dict[str, Any]) -> Optional[str]:
        """Detect primary programming language."""
        languages = language_index.get("languages", {})
        if not languages:
            return None
        
        # Return language with most files
        return max(languages.items(), key=lambda x: len(x[1]))[0] if languages else None
    
    def _build_agent_context(
        self,
        area: Dict[str, Any],
        surface_map: SurfaceMap,
        language_index: Dict[str, Any]
    ) -> str:
        """Build context for specialized agent."""
        context = f"""Analyze the following code for {area.get('risk_type', 'security')} vulnerabilities:

Location: {area.get('location', 'N/A')}
Risk Type: {area.get('risk_type', 'N/A')}
Reason: {area.get('reason', 'N/A')}

Context:
- Target: {surface_map.target}
- Target Type: {surface_map.target_type}
- Entry Points: {len(surface_map.entry_points)} identified
- Languages: {', '.join(language_index.get('languages', {}).keys())}

Please analyze the code at the specified location and identify:
1. Potential vulnerabilities
2. Preconditions required for exploitation
3. Evidence supporting the finding
4. Suggested CWE ID

Format your response as JSON:
{{
    "vulnerabilities": [
        {{
            "location": "file:line or function",
            "bug_class": "...",
            "precondition": "...",
            "evidence": "...",
            "cwe_id": "CWE-XXX",
            "confidence": 0.0-1.0
        }}
    ]
}}
"""
        return context
    
    def _build_agent_context_from_hypothesis(
        self,
        hypothesis: Dict[str, Any],
        surface_map: SurfaceMap,
        language_index: Dict[str, Any]
    ) -> str:
        """Build context from threat hypothesis."""
        context = f"""Validate the following threat hypothesis:

Location: {hypothesis.get('location', 'N/A')}
Threat Type: {hypothesis.get('threat_type', 'N/A')}
Precondition: {hypothesis.get('precondition', 'N/A')}
Likelihood: {hypothesis.get('likelihood', 'N/A')}

Context:
- Target: {surface_map.target}
- Target Type: {surface_map.target_type}

Please analyze the code at the specified location and determine:
1. Whether the threat hypothesis is valid
2. Specific vulnerability details
3. Preconditions required for exploitation
4. Evidence supporting or refuting the hypothesis
5. Appropriate CWE ID

Format your response as JSON:
{{
    "vulnerabilities": [
        {{
            "location": "file:line or function",
            "bug_class": "...",
            "precondition": "...",
            "evidence": "...",
            "cwe_id": "CWE-XXX",
            "confidence": 0.0-1.0
        }}
    ]
}}
"""
        return context
    
    def _run_specialized_agent(
        self,
        bug_class: BugClass,
        location: str,
        model: str,
        context: str
    ) -> List[CandidateFinding]:
        """
        Run a specialized auditor agent.
        
        Args:
            bug_class: Bug class to analyze
            location: Code location to analyze
            model: OpenRouter model to use
            context: Analysis context
            
        Returns:
            List of candidate findings
        """
        findings = []
        
        try:
            # Check budget before making request
            if self.cost_tracker.is_budget_exceeded():
                logger.warning("Budget exceeded, skipping agent scan")
                return findings
            
            # Call OpenRouter
            response = self.client.chat(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": f"You are a specialized security auditor focusing on {bug_class.value.replace('_', ' ')} vulnerabilities. Analyze code thoroughly and provide detailed findings with evidence."
                    },
                    {
                        "role": "user",
                        "content": context
                    }
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            
            # Estimate cost and track
            estimated_cost = self._estimate_request_cost(model, response)
            if not self.cost_tracker.add_cost(model, estimated_cost, stage="scan"):
                logger.warning(f"Cost budget exceeded for {model}")
                return findings
            
            # Parse response
            vulnerabilities = self._parse_agent_response(response["content"])
            
            # Create CandidateFinding objects
            for vuln in vulnerabilities:
                finding = CandidateFinding(
                    bug_class=bug_class,
                    location=vuln.get("location", location),
                    precondition=vuln.get("precondition", ""),
                    evidence=vuln.get("evidence", ""),
                    hypothesis_score=vuln.get("confidence", 0.5),
                    cwe_id=vuln.get("cwe_id"),
                    agent_used=model
                )
                findings.append(finding)
            
        except Exception as e:
            logger.error(f"Failed to run agent for {bug_class.value} at {location}: {e}")
        
        return findings
    
    def _parse_agent_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse agent response for vulnerabilities."""
        import json
        import re
        
        # Try to extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', response)
        
        if json_match:
            try:
                data = json.loads(json_match.group())
                return data.get("vulnerabilities", [])
            except json.JSONDecodeError:
                logger.warning("Failed to parse JSON from agent response")
        
        # Fallback: create a single vulnerability from text
        return [{
            "location": "unknown",
            "bug_class": "unknown",
            "precondition": "unknown",
            "evidence": response[:500],  # Truncate if too long
            "cwe_id": None,
            "confidence": 0.3
        }]
    
    def _estimate_request_cost(self, model: str, response: Dict[str, Any]) -> float:
        """Estimate cost for a request."""
        # Rough estimation based on token count
        usage = response.get("usage", {})
        total_tokens = usage.get("total_tokens", 1000)
        
        # Cost per 1K tokens (rough estimate)
        cost_per_1k = 0.001  # Conservative estimate
        
        return (total_tokens / 1000) * cost_per_1k

"""
OpenRouter SDK client wrapper for the multi-model agentic security pipeline.
"""
import os
from typing import List, Dict, Any, Optional, Generator
import logging
from openrouter import OpenRouter

logger = logging.getLogger(__name__)


class OpenRouterClient:
    """Wrapper for OpenRouter SDK with cost tracking and model selection."""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://openrouter.ai/api/v1",
        timeout_seconds: int = 120,
        max_retries: int = 3
    ):
        """
        Initialize OpenRouter client.
        
        Args:
            api_key: OpenRouter API key (defaults to OPENROUTER_API_KEY env var)
            base_url: Base URL for OpenRouter API
            timeout_seconds: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
        """
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError(
                "OpenRouter API key not provided. "
                "Set OPENROUTER_API_KEY environment variable or pass api_key parameter."
            )
        
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.total_cost_usd = 0.0
        self.request_count = 0
        
        # Initialize OpenRouter client
        self._client = OpenRouter(api_key=self.api_key)
        logger.info("OpenRouter client initialized")
    
    def chat(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Send a chat completion request.
        
        Args:
            model: Model identifier (e.g., "anthropic/claude-3.5-sonnet")
            messages: List of message dictionaries with 'role' and 'content'
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            stream: Whether to stream the response
            **kwargs: Additional parameters for the API
            
        Returns:
            Response dictionary with content and metadata
        """
        try:
            response = self._client.chat.send(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=stream,
                **kwargs
            )
            
            # Track cost (if available in response)
            self.request_count += 1
            if hasattr(response, 'usage') and response.usage:
                # OpenRouter may provide cost info in usage
                if hasattr(response.usage, 'total_cost'):
                    self.total_cost_usd += response.usage.total_cost
            
            return {
                "content": response.choices[0].message.content,
                "model": model,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens if hasattr(response, 'usage') else 0,
                    "completion_tokens": response.usage.completion_tokens if hasattr(response, 'usage') else 0,
                    "total_tokens": response.usage.total_tokens if hasattr(response, 'usage') else 0
                },
                "finish_reason": response.choices[0].finish_reason if response.choices else None
            }
        except Exception as e:
            logger.error(f"OpenRouter chat request failed: {e}")
            raise
    
    def chat_stream(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> Generator[str, None, None]:
        """
        Send a streaming chat completion request.
        
        Args:
            model: Model identifier
            messages: List of message dictionaries
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            **kwargs: Additional parameters
            
        Yields:
            Content chunks as they are generated
        """
        try:
            stream = self._client.chat.send(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
                **kwargs
            )
            
            self.request_count += 1
            full_content = ""
            
            for event in stream:
                if event.choices and event.choices[0].delta.content:
                    chunk = event.choices[0].delta.content
                    full_content += chunk
                    yield chunk
            
            # Update cost tracking after stream completes
            self.total_cost_usd += self._estimate_cost(model, len(full_content))
            
        except Exception as e:
            logger.error(f"OpenRouter chat stream failed: {e}")
            raise
    
    def embedding(
        self,
        model: str,
        input_text: str,
        **kwargs
    ) -> List[float]:
        """
        Generate embeddings for text.
        
        Args:
            model: Embedding model identifier
            input_text: Text to embed
            **kwargs: Additional parameters
            
        Returns:
            Embedding vector as list of floats
        """
        try:
            response = self._client.embeddings.create(
                model=model,
                input=input_text,
                **kwargs
            )
            
            self.request_count += 1
            embedding = response.data[0].embedding
            
            # Estimate cost for embeddings
            self.total_cost_usd += self._estimate_embedding_cost(model, len(input_text))
            
            return embedding
        except Exception as e:
            logger.error(f"OpenRouter embedding request failed: {e}")
            raise
    
    def get_total_cost(self) -> float:
        """Get total cost incurred in USD."""
        return self.total_cost_usd
    
    def get_request_count(self) -> int:
        """Get total number of requests made."""
        return self.request_count
    
    def reset_cost_tracking(self):
        """Reset cost tracking counters."""
        self.total_cost_usd = 0.0
        self.request_count = 0
        logger.info("Cost tracking reset")
    
    def _estimate_cost(self, model: str, output_tokens: int) -> float:
        """
        Estimate cost for a request based on model and token count.
        
        This is a rough estimation. Actual costs may vary.
        """
        # Rough cost estimates per 1M tokens (input + output)
        cost_per_1m = {
            "claude-3.5-sonnet": 15.0,
            "gpt-4": 30.0,
            "gemini-pro": 7.0,
            "text-embedding-3-small": 0.02,
        }
        
        # Default fallback
        base_cost = cost_per_1m.get(model.split("/")[-1], 10.0)
        
        # Estimate based on output tokens (assuming similar input length)
        estimated_tokens = output_tokens * 2  # Rough estimate
        cost = (estimated_tokens / 1_000_000) * base_cost
        
        return cost
    
    def _estimate_embedding_cost(self, model: str, input_length: int) -> float:
        """Estimate cost for embedding request."""
        # Embeddings are much cheaper
        cost_per_1m = 0.02  # Typical embedding cost
        estimated_tokens = input_length / 4  # Rough token estimate
        cost = (estimated_tokens / 1_000_000) * cost_per_1m
        return cost
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        logger.info(f"OpenRouter session ended. Total cost: ${self.total_cost_usd:.4f}, Requests: {self.request_count}")

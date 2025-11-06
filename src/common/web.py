"""HTTP client with retry and backoff."""
import time
import logging
from typing import Optional, Dict, Any
from requests import Session, RequestException
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class RetrySession(Session):
    """Requests session with automatic retry and backoff."""
    
    def __init__(
        self,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        status_forcelist: Optional[list] = None,
        trust_env: bool = True,
    ):
        super().__init__()
        # Allow callers to opt-out of inheriting proxy and certificate settings
        # from the running environment. This is useful when communicating with
        # services that are only reachable on a private network where the
        # configured corporate proxy would block the request (for example,
        # 172.x.x.x addresses in lab environments).
        self.trust_env = trust_env
        if status_forcelist is None:
            status_forcelist = [500, 502, 503, 504]
        
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
            allowed_methods=["GET", "POST", "PUT"],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.mount("http://", adapter)
        self.mount("https://", adapter)
    
    def request_with_backoff(self, *args, **kwargs) -> Any:
        """Make request with exponential backoff on failure."""
        max_attempts = 4
        for attempt in range(max_attempts):
            try:
                return self.request(*args, **kwargs)
            except RequestException as e:
                if attempt == max_attempts - 1:
                    raise
                wait = 2 ** attempt
                logger.warning(
                    f"Request failed (attempt {attempt + 1}/{max_attempts}): {e}. "
                    f"Retrying in {wait}s..."
                )
                time.sleep(wait)
        
        raise RequestException("Max retries exceeded")


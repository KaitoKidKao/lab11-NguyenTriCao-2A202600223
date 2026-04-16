"""
Assignment 11: RateLimitPlugin
Prevent abuse by limiting how many requests a user can send in a time window.
"""
from collections import defaultdict, deque
import time
from google.genai import types
from google.adk.plugins import base_plugin

class RateLimitPlugin(base_plugin.BasePlugin):
    """Sliding window rate limiter per user."""
    
    def __init__(self, max_requests=10, window_seconds=60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows = defaultdict(deque)  # user_id -> deque of timestamps
        self.blocked_count = 0
        self.total_count = 0

    async def on_user_message_callback(self, *, invocation_context, user_message, **kwargs):
        """Check rate limit for the user."""
        self.total_count += 1
        user_id = invocation_context.user_id if invocation_context else "anonymous"
        now = time.time()
        window = self.user_windows[user_id]

        # 1. Remove expired timestamps from the front of the deque
        while window and window[0] <= now - self.window_seconds:
            window.popleft()

        # 2. Check if len(window) >= self.max_requests
        if len(window) >= self.max_requests:
            self.blocked_count += 1
            wait_time = int(self.window_seconds - (now - window[0]))
            block_message = f"Rate limit exceeded. Please wait {wait_time} seconds before sending more requests."
            
            return types.Content(
                role="model",
                parts=[types.Part.from_text(text=block_message)],
            )

        # 3. Add current timestamp (allow)
        window.append(now)
        return None  # Allow request through

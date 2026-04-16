"""
Monitoring and Audit Log plugins for Lab 11 Security Pipeline.
Provides real-time metrics tracking and threshold-based alerts.
"""
import time
import json
import re
from datetime import datetime
from collections import defaultdict
from google.adk.plugins import base_plugin

class AuditLogPlugin(base_plugin.BasePlugin):
    """Logs all interactions for security audit and compliance."""
    
    def __init__(self, log_path="security_audit.json"):
        super().__init__(name="audit_log")
        self.log_path = log_path
        self.logs = []
        self._pending = {}  # user_id -> interaction_info

    def _extract_text(self, content_or_response) -> str:
        """Helper to extract text from ADK Content or LlmResponse objects."""
        content = getattr(content_or_response, "content", content_or_response)
        text = ""
        if content and hasattr(content, "parts") and content.parts:
            for part in content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    async def on_user_message_callback(self, *, invocation_context=None, user_message=None, **kwargs):
        """Called when a user sends a message. Initializes the log entry."""
        try:
            user_id = invocation_context.user_id if invocation_context else "anonymous"
            session_id = invocation_context.session_id if invocation_context else "unknown"
            
            self._pending[user_id] = {
                "start_time": time.perf_counter(),
                "input": self._extract_text(user_message),
                "timestamp": datetime.now().isoformat(),
                "session_id": session_id
            }
        except Exception as e:
            print(f"[ERROR] AuditLog.on_user_message: {e}")
        return None

    async def after_model_callback(self, *, invocation_context=None, llm_response=None, **kwargs):
        """Called after the model generates a response. Finalizes the log entry."""
        try:
            user_id = invocation_context.user_id if invocation_context else "anonymous"
            if user_id in self._pending:
                info = self._pending.pop(user_id)
                latency = (time.perf_counter() - info["start_time"]) * 1000
                
                output_text = self._extract_text(llm_response)
                
                # Identify if it was blocked by our guardrails
                is_blocked = any(msg in output_text for msg in [
                    "Security Alert", 
                    "I'm a VinBank assistant and can only help with banking",
                    "cannot provide that information",
                    "quality standards"
                ])

                log_entry = {
                    "timestamp": info["timestamp"],
                    "user_id": user_id,
                    "session_id": info["session_id"],
                    "user_message": info["input"],
                    "response": output_text,
                    "latency_ms": round(latency, 2),
                    "blocked": is_blocked
                }
                self.logs.append(log_entry)
                self._save_logs()
        except Exception as e:
            print(f"[ERROR] AuditLog.after_model: {e}")
            
        return llm_response

    def _save_logs(self):
        """Persist logs to a JSON file."""
        try:
            with open(self.log_path, "w", encoding="utf-8") as f:
                json.dump(self.logs, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Failed to save logs: {e}")

class MonitoringService:
    """Monitors audit logs and fires alerts when safety thresholds are exceeded."""
    
    def __init__(self, audit_plugin: AuditLogPlugin, block_threshold=0.3):
        self.audit_plugin = audit_plugin
        self.block_threshold = block_threshold
        self.last_alert_time = 0

    def check_alerts(self):
        """Check the last 10 requests and fire an alert if block rate is too high."""
        recent_logs = self.audit_plugin.logs[-10:]
        if len(recent_logs) < 5:
            return  # Not enough data for alerting

        block_count = sum(1 for log in recent_logs if log["blocked"])
        block_rate = block_count / len(recent_logs)

        if block_rate > self.block_threshold:
            print("\n" + "!" * 60)
            print(f"[SECURITY ALERT] High block rate detected: {block_rate:.0%}")
            print(f"Timestamp: {datetime.now().isoformat()}")
            print(f"Action: Consider investigating session {recent_logs[-1]['session_id'] or 'N/A'}")
            print("!" * 60 + "\n")
            return True
        return False

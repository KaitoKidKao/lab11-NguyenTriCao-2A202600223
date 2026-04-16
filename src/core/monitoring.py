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
                block_reasons = []
                if "Security Alert" in output_text: block_reasons.append("RateLimit/InputGuard")
                if "can only help with banking" in output_text: block_reasons.append("NeMo/Out-of-Scope")
                if "cannot provide that information" in output_text: block_reasons.append("OutputGuard/Judge")
                if "quality standards" in output_text: block_reasons.append("OutputGuard/Judge")

                log_entry = {
                    "timestamp": info["timestamp"],
                    "user_id": user_id,
                    "session_id": info["session_id"],
                    "user_message": info["input"],
                    "response": output_text,
                    "latency_ms": round(latency, 2),
                    "blocked": len(block_reasons) > 0,
                    "block_reasons": block_reasons
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

class MonitoringAlert:
    """Specialized monitoring service that tracks specific security metrics."""
    
    def __init__(self, audit_plugin: AuditLogPlugin):
        self.audit_plugin = audit_plugin
        self.thresholds = {
            "block_rate": 0.4,       # Alert if > 40% blocked in last window
            "latency_p95": 5000,    # Alert if p95 latency > 5s
            "rate_limit_hits": 3     # Alert if > 3 rate limit blocks in last window
        }
        self.alert_history = []

    def evaluate_metrics(self, window_size=10):
        """Analyze recent logs and fire alerts if thresholds are exceeded."""
        recent = self.audit_plugin.logs[-window_size:]
        if len(recent) < 5:
            return []

        active_alerts = []
        
        # 1. Block Rate
        blocked = [l for l in recent if l["blocked"]]
        block_rate = len(blocked) / len(recent)
        if block_rate > self.thresholds["block_rate"]:
            active_alerts.append(f"CRITICAL: High Block Rate ({block_rate:.0%})")

        # 2. Rate Limit Hits
        rl_hits = sum(1 for l in blocked if "RateLimit" in str(l.get("block_reasons", "")))
        if rl_hits >= self.thresholds["rate_limit_hits"]:
            active_alerts.append(f"WARNING: Potential DoS Attack (Rate limit hits: {rl_hits})")

        # 3. Latency
        latencies = sorted([l["latency_ms"] for l in recent])
        p95 = latencies[int(len(latencies) * 0.95)]
        if p95 > self.thresholds["latency_p95"]:
            active_alerts.append(f"PERFORMANCE: High p95 Latency ({p95:.0f}ms)")

        if active_alerts:
            self._fire_alerts(active_alerts)
        
        return active_alerts

    def _fire_alerts(self, alerts):
        """Console output for alerts (mocking a real alerting system)."""
        print("\n" + "!" * 60)
        print("SEC-OPS ALERT DASHBOARD")
        print(f"Timestamp: {datetime.now().strftime('%H:%M:%S')}")
        for alert in alerts:
            print(f" >> {alert}")
        print("!" * 60 + "\n")
        self.alert_history.extend(alerts)

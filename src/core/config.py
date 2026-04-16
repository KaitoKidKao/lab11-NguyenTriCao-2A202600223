"""
Lab 11 — Configuration & API Key Setup
"""
import os


from dotenv import load_dotenv

def setup_api_key():
    """Load API keys from .env or environment."""
    load_dotenv()
    if "OPENAI_API_KEY" not in os.environ:
        print("Warning: OPENAI_API_KEY not found in environment.")
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"

setup_api_key()
print("Configuration loaded from .env")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]

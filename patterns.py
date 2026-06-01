import re

# Each pattern: (name, compiled_regex, severity)
PATTERNS = [
    # AWS
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("AWS Secret Access Key", re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"), "critical"),

    # Private keys
    ("Private Key (PEM)", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("Private Key (PEM) ENCRYPTED", re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"), "critical"),

    # GitHub
    ("GitHub Token (classic)", re.compile(r"ghp_[0-9a-zA-Z]{36}"), "critical"),
    ("GitHub OAuth Token", re.compile(r"gho_[0-9a-zA-Z]{36}"), "critical"),
    ("GitHub App Token", re.compile(r"(ghu|ghs|ghr)_[0-9a-zA-Z]{36}"), "critical"),

    # Slack
    ("Slack Bot Token", re.compile(r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}"), "critical"),
    ("Slack User Token", re.compile(r"xoxp-[0-9]+-[0-9]+-[0-9]+-[0-9a-f]+"), "critical"),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+"), "high"),

    # Google
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "critical"),
    ("Google OAuth Client Secret", re.compile(r"(?i)client.?secret['\"\s:=]+[0-9a-zA-Z\-_]{24}"), "high"),

    # Anthropic / OpenAI
    ("Anthropic API Key", re.compile(r"sk-ant-[0-9a-zA-Z\-_]{93}"), "critical"),
    ("OpenAI API Key", re.compile(r"sk-[0-9a-zA-Z]{48}"), "critical"),

    # Generic credential assignments in config/env files
    ("Password assignment", re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?.{6,}"), "high"),
    ("Secret key assignment", re.compile(r"(?i)(?:secret[_-]?key|api[_-]?secret|app[_-]?secret)\s*[=:]\s*['\"]?[^\s'\"{]{8,}"), "high"),
    ("Token assignment", re.compile(r"(?i)(?:auth[_-]?token|access[_-]?token|bearer[_-]?token)\s*[=:]\s*['\"]?[^\s'\"{]{16,}"), "high"),
    ("Generic API key assignment", re.compile(r"(?i)api[_-]?key\s*[=:]\s*['\"]?[^\s'\"{]{16,}"), "high"),

    # Connection strings
    ("Database connection string", re.compile(r"(?i)(postgres|mysql|mongodb|redis|mssql)://[^:]+:[^@]+@"), "critical"),
    ("JDBC connection string", re.compile(r"jdbc:[a-zA-Z0-9]+://[^\s]+password=[^\s&]+"), "critical"),

    # Private certs / tokens
    ("JWT token", re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"), "medium"),
    ("SSH private key header", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), "critical"),
]

# File extensions to skip entirely
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".wav", ".ogg", ".flac",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".pyc",
    ".lock",  # package-lock.json etc — rarely contain secrets, very noisy
}

# Directory names to skip
SKIP_DIRS = {
    "node_modules", "venv", ".venv", "env", ".env",
    "build", "dist", ".git", "__pycache__",
    ".tox", ".mypy_cache", ".pytest_cache",
    "target",  # Java/Rust build output
}

"""
Constants and configuration values for ClaudeCode.
"""

import os

# API Configuration
DEFAULT_CLAUDE_MODEL = os.environ.get('CLAUDE_MODEL') or 'claude-opus-4-1-20250805'
DEFAULT_TIMEOUT_SECONDS = 180  # 3 minutes
VALIDATION_TIMEOUT_SECONDS = 30
DEFAULT_MAX_RETRIES = 3
RATE_LIMIT_BACKOFF_MAX = 30  # Maximum backoff time for rate limits

# Token Limits
PROMPT_TOKEN_LIMIT = 16384  # 16k tokens max for claude-opus-4

# Exit Codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_CONFIGURATION_ERROR = 2

# Subprocess Configuration
SUBPROCESS_TIMEOUT = 1200  # 20 minutes for Claude Code execution

# GitHub credentials removed from the Claude Code environment: the PR checkout
# is untrusted, and the CLI's tools could otherwise read them.
GITHUB_TOKEN_VARS = frozenset({
    'GITHUB_TOKEN',
    'GH_TOKEN',
    'ACTIONS_RUNTIME_TOKEN',
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
    'ACTIONS_ID_TOKEN_REQUEST_URL',
})


# Static analysis findings (e.g. Semgrep) passed to Claude as leads. The caller
# caps them too; these limits keep the prompt bounded whatever the input.
MAX_STATIC_ANALYSIS_FINDINGS = 50
MAX_STATIC_ANALYSIS_MESSAGE_CHARS = 500

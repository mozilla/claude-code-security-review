"""Tests for ClaudeAPIClient.validate_api_access."""

from unittest.mock import MagicMock, patch

from claudecode.claude_api_client import ClaudeAPIClient
from claudecode.constants import VALIDATION_TIMEOUT_SECONDS


@patch('claudecode.claude_api_client.Anthropic')
def test_validate_api_access_checks_configured_model(mock_anthropic):
    client = ClaudeAPIClient(model='claude-test-model', api_key='test-key')

    valid, error = client.validate_api_access()

    assert valid is True
    assert error == ''
    mock_anthropic.return_value.messages.create.assert_called_once_with(
        model='claude-test-model',
        max_tokens=1,
        messages=[{"role": "user", "content": "Hello"}],
        timeout=VALIDATION_TIMEOUT_SECONDS,
    )


@patch('claudecode.claude_api_client.Anthropic')
def test_validate_api_access_reports_failure(mock_anthropic):
    mock_anthropic.return_value.messages.create = MagicMock(side_effect=Exception('404 model not found'))
    client = ClaudeAPIClient(model='claude-retired-model', api_key='test-key')

    valid, error = client.validate_api_access()

    assert valid is False
    assert '404 model not found' in error


@patch('claudecode.claude_api_client.Anthropic')
def test_read_file_stays_inside_repo(mock_anthropic, tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n")
    (tmp_path / "secret.txt").write_text("secret\n")
    (repo / "link.txt").symlink_to(tmp_path / "secret.txt")
    monkeypatch.setenv("REPO_PATH", str(repo))
    client = ClaudeAPIClient(model='claude-test-model', api_key='test-key')

    assert client._read_file("app.py")[0] is True
    for path in ["../secret.txt", str(tmp_path / "secret.txt"), "link.txt", "/proc/self/environ"]:
        ok, content, error = client._read_file(path)
        assert ok is False and "outside the repository" in error

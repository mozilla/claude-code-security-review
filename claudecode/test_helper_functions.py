"""Unit tests for helper functions in github_action_audit module."""

import pytest
import json
import os
from unittest.mock import patch, MagicMock


from claudecode.github_action_audit import (
    get_environment_config,
    initialize_clients,
    initialize_findings_filter,
    run_security_audit,
    apply_findings_filter,
    load_static_analysis_findings,
    ConfigurationError,
    AuditError
)
from claudecode.findings_filter import FindingsFilter


class TestHelperFunctions:
    """Test helper functions in github_action_audit module."""
    
    def test_get_environment_config_success(self):
        """Test successful environment configuration retrieval."""
        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123'
        }):
            repo_name, pr_number = get_environment_config()
            
            assert repo_name == 'owner/repo'
            assert pr_number == 123
    
    def test_get_environment_config_missing_repository(self):
        """Test error when GITHUB_REPOSITORY is missing."""
        with patch.dict(os.environ, {'PR_NUMBER': '123'}, clear=True):
            with pytest.raises(ConfigurationError) as exc_info:
                get_environment_config()
            
            assert "GITHUB_REPOSITORY environment variable required" in str(exc_info.value)
    
    def test_get_environment_config_missing_pr_number(self):
        """Test error when PR_NUMBER is missing."""
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'owner/repo'}, clear=True):
            with pytest.raises(ConfigurationError) as exc_info:
                get_environment_config()
            
            assert "PR_NUMBER environment variable required" in str(exc_info.value)
    
    def test_get_environment_config_invalid_pr_number(self):
        """Test error when PR_NUMBER is not a valid integer."""
        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': 'not-a-number'
        }):
            with pytest.raises(ConfigurationError) as exc_info:
                get_environment_config()
            
            assert "Invalid PR_NUMBER" in str(exc_info.value)
    
    @patch('claudecode.github_action_audit.GitHubActionClient')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    def test_initialize_clients_success(self, mock_claude_runner, mock_github_client):
        """Test successful client initialization."""
        mock_github_instance = MagicMock()
        mock_claude_instance = MagicMock()
        mock_github_client.return_value = mock_github_instance
        mock_claude_runner.return_value = mock_claude_instance
        
        github_client, claude_runner = initialize_clients()
        
        assert github_client == mock_github_instance
        assert claude_runner == mock_claude_instance
        mock_github_client.assert_called_once()
        mock_claude_runner.assert_called_once()
    
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_initialize_clients_github_failure(self, mock_github_client):
        """Test error when GitHub client initialization fails."""
        mock_github_client.side_effect = Exception("GitHub API error")
        
        with pytest.raises(ConfigurationError) as exc_info:
            initialize_clients()
        
        assert "Failed to initialize GitHub client" in str(exc_info.value)
        assert "GitHub API error" in str(exc_info.value)
    
    @patch('claudecode.github_action_audit.GitHubActionClient')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    def test_initialize_clients_claude_failure(self, mock_claude_runner, mock_github_client):
        """Test error when Claude runner initialization fails."""
        mock_github_client.return_value = MagicMock()
        mock_claude_runner.side_effect = Exception("Claude init error")
        
        with pytest.raises(ConfigurationError) as exc_info:
            initialize_clients()
        
        assert "Failed to initialize Claude runner" in str(exc_info.value)
        assert "Claude init error" in str(exc_info.value)
    
    @patch('claudecode.github_action_audit.FindingsFilter')
    def test_initialize_findings_filter_with_claude(self, mock_filter):
        """Test initializing findings filter with Claude API enabled."""
        mock_filter_instance = MagicMock()
        mock_filter.return_value = mock_filter_instance
        
        with patch.dict(os.environ, {
            'ENABLE_CLAUDE_FILTERING': 'true',
            'ANTHROPIC_API_KEY': 'test-key-123'
        }):
            result = initialize_findings_filter()
            
            assert result == mock_filter_instance
            mock_filter.assert_called_once_with(
                use_hard_exclusions=True,
                use_claude_filtering=True,
                api_key='test-key-123',
                custom_filtering_instructions=None
            )
    
    @patch('claudecode.github_action_audit.FindingsFilter')
    def test_initialize_findings_filter_without_claude(self, mock_simple_filter):
        """Test initializing findings filter without Claude API."""
        mock_filter_instance = MagicMock()
        mock_simple_filter.return_value = mock_filter_instance
        
        with patch.dict(os.environ, {
            'ENABLE_CLAUDE_FILTERING': 'false'
        }, clear=True):
            result = initialize_findings_filter()
            
            assert result == mock_filter_instance
            mock_simple_filter.assert_called_once()
    
    @patch('claudecode.github_action_audit.FindingsFilter')
    def test_initialize_findings_filter_with_defaults(self, mock_simple_filter):
        """Test initializing findings filter with defaults."""
        mock_filter_instance = MagicMock()
        mock_simple_filter.return_value = mock_filter_instance
        
        with patch.dict(os.environ, {}, clear=True):
            result = initialize_findings_filter()
            
            assert result == mock_filter_instance
    
    def test_run_security_audit_success(self):
        """Test successful security audit execution."""
        mock_runner = MagicMock()
        mock_runner.run_security_audit.return_value = (
            True,
            "",
            {"findings": [{"id": 1}], "analysis_summary": {}}
        )
        
        result = run_security_audit(mock_runner, "test prompt")
        
        assert result == {"findings": [{"id": 1}], "analysis_summary": {}}
        mock_runner.run_security_audit.assert_called_once()
    
    def test_run_security_audit_failure(self):
        """Test security audit execution failure."""
        mock_runner = MagicMock()
        mock_runner.run_security_audit.return_value = (
            False,
            "Audit failed: timeout",
            {}
        )
        
        with pytest.raises(AuditError) as exc_info:
            run_security_audit(mock_runner, "test prompt")
        
        assert "Security audit failed: Audit failed: timeout" in str(exc_info.value)
    
    def test_apply_findings_filter_with_findings_filter(self):
        """Test applying FindingsFilter to findings."""
        mock_filter = MagicMock(spec=FindingsFilter)
        mock_filter.filter_findings.return_value = (
            True,
            {
                'filtered_findings': [{"id": 1}],
                'excluded_findings': [{"id": 2}],
                'analysis_summary': {'total': 2, 'kept': 1}
            },
            MagicMock()  # filter_stats
        )
        
        original_findings = [{"id": 1}, {"id": 2}]
        pr_context = {"repo_name": "test/repo"}
        
        # Create mock github client
        mock_github_client = MagicMock()
        mock_github_client._is_excluded.return_value = False
        
        kept, excluded, summary = apply_findings_filter(
            mock_filter, original_findings, pr_context, mock_github_client
        )
        
        assert kept == [{"id": 1}]
        assert excluded == [{"id": 2}]
        assert summary == {'total': 2, 'kept': 1, 'directory_excluded_count': 0}
        
        mock_filter.filter_findings.assert_called_once_with(original_findings, pr_context)
    
    def test_apply_findings_filter_with_simple_filter(self):
        """Test applying FindingsFilter to findings."""
        mock_filter = MagicMock(spec=FindingsFilter)
        mock_filter.filter_findings.return_value = (
            True,
            {
                'filtered_findings': [{"id": 1}],
                'excluded_findings': [{"id": 2}],
                'analysis_summary': {}
            },
            MagicMock()  # filter_stats
        )
        
        original_findings = [{"id": 1}, {"id": 2}]
        pr_context = {"repo_name": "test/repo"}
        
        # Create mock github client
        mock_github_client = MagicMock()
        mock_github_client._is_excluded.return_value = False
        
        kept, excluded, summary = apply_findings_filter(
            mock_filter, original_findings, pr_context, mock_github_client
        )
        
        assert kept == [{"id": 1}]
        assert excluded == [{"id": 2}]
        assert summary == {'directory_excluded_count': 0}
        
        mock_filter.filter_findings.assert_called_once_with(original_findings, pr_context)
    
    def test_apply_findings_filter_failure(self):
        """Test handling of filter failure."""
        mock_filter = MagicMock(spec=FindingsFilter)
        mock_filter.filter_findings.return_value = (
            False,  # filter failed
            {},
            MagicMock()
        )
        
        original_findings = [{"id": 1}, {"id": 2}]
        pr_context = {"repo_name": "test/repo"}
        
        # Create mock github client
        mock_github_client = MagicMock()
        mock_github_client._is_excluded.return_value = False
        
        kept, excluded, summary = apply_findings_filter(
            mock_filter, original_findings, pr_context, mock_github_client
        )
        
        # On failure, should keep all findings
        assert kept == original_findings
        assert excluded == []
        assert summary == {'directory_excluded_count': 0}


class TestLoadStaticAnalysisFindings:
    """Test loading static analysis findings passed to Claude as leads."""

    FINDING = {
        "tool": "semgrep",
        "rule_id": "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
        "severity": "error",
        "path": "src/app.py",
        "start_line": 12,
        "end_line": 13,
        "message": "Detected user input used to manually construct a SQL string.",
    }

    def _write(self, tmp_path, content):
        path = tmp_path / "findings.json"
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        return str(path)

    def test_no_path(self):
        assert load_static_analysis_findings("") == ([], 0)

    def test_missing_file(self, tmp_path):
        assert load_static_analysis_findings(str(tmp_path / "missing.json")) == ([], 0)

    def test_invalid_json(self, tmp_path):
        assert load_static_analysis_findings(self._write(tmp_path, "{not json")) == ([], 0)

    @pytest.mark.parametrize("content", [[], {"omitted": 2}, {"findings": "x"}])
    def test_unexpected_format(self, tmp_path, content):
        assert load_static_analysis_findings(self._write(tmp_path, content)) == ([], 0)

    def test_valid_findings(self, tmp_path):
        path = self._write(tmp_path, {"findings": [self.FINDING], "omitted": 4})
        assert load_static_analysis_findings(path) == ([self.FINDING], 4)

    def test_malformed_entries_dropped(self, tmp_path):
        no_rule = {k: v for k, v in self.FINDING.items() if k != "rule_id"}
        bad_line = dict(self.FINDING, start_line="twelve")
        path = self._write(tmp_path, {"findings": ["text", no_rule, bad_line, self.FINDING], "omitted": "x"})
        assert load_static_analysis_findings(path) == ([self.FINDING], 0)

    @pytest.mark.parametrize("omitted, expected", [(True, 0), (3.0, 3), (-2, 0), ("3", 0), (None, 0)])
    def test_omitted_must_be_a_number(self, tmp_path, omitted, expected):
        path = self._write(tmp_path, {"findings": [self.FINDING], "omitted": omitted})
        assert load_static_analysis_findings(path) == ([self.FINDING], expected)

    @pytest.mark.parametrize("start_line", [True, 0, -3, 1.5, "12", None, "Infinity", "NaN", "1e400"])
    def test_invalid_start_line_drops_entry(self, tmp_path, start_line):
        # The JSON literals Infinity, NaN and 1e400 parse to non-finite floats
        raw = json.dumps(start_line) if start_line not in ("Infinity", "NaN", "1e400") else start_line
        finding = json.dumps(dict(self.FINDING, start_line="__LINE__")).replace('"__LINE__"', raw)
        path = self._write(tmp_path, '{"findings": [%s, %s]}' % (finding, json.dumps(self.FINDING)))
        assert load_static_analysis_findings(path) == ([self.FINDING], 0)

    @pytest.mark.parametrize("end_line", [None, True, "13", 1.5, 5, "Infinity"])
    def test_invalid_end_line_falls_back_to_start_line(self, tmp_path, end_line):
        raw = json.dumps(end_line) if end_line != "Infinity" else end_line
        finding = json.dumps(dict(self.FINDING, end_line="__LINE__")).replace('"__LINE__"', raw)
        findings, _ = load_static_analysis_findings(self._write(tmp_path, '{"findings": [%s]}' % finding))
        assert findings[0]["start_line"] == 12 and findings[0]["end_line"] == 12

    def test_whole_float_lines_accepted(self, tmp_path):
        path = self._write(tmp_path, {"findings": [dict(self.FINDING, start_line=12.0, end_line=13.0)]})
        assert load_static_analysis_findings(path) == ([self.FINDING], 0)

    def test_end_line_defaults_to_start_line(self, tmp_path):
        finding = {k: v for k, v in self.FINDING.items() if k != "end_line"}
        findings, _ = load_static_analysis_findings(self._write(tmp_path, {"findings": [finding]}))
        assert findings[0]["end_line"] == 12

    def test_cap_and_truncation(self, tmp_path):
        long = dict(self.FINDING, message="m" * 2000)
        path = self._write(tmp_path, {"findings": [long] * 60, "omitted": 5})
        findings, omitted = load_static_analysis_findings(path)
        assert len(findings) == 50
        assert omitted == 15
        assert len(findings[0]["message"]) == 500

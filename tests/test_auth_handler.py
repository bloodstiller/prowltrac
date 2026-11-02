"""
Tests for bearer token authentication in AuthHandler.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from src.auth.auth_handler import AuthenticationError, AuthHandler


def make_response(status_code=200, json_data=None, text=""):
    """Build a fake requests.Response-like object."""
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_data or {}
    response.text = text
    response.headers = {}
    return response


class TestAuthenticateWithToken:
    """Test cases for direct bearer token authentication."""

    def setup_method(self):
        self.auth = AuthHandler(use_cache=False)
        self.url = "https://test.plextrac.com"
        self.token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test"

    def test_authenticate_with_token_success(self):
        self.auth.session.request = MagicMock(
            return_value=make_response(
                status_code=200, json_data={"username": "svc-user", "tenant_id": "abc"}
            )
        )

        result = self.auth.authenticate_with_token(self.token, url=self.url)

        assert result is True
        assert self.auth.token == self.token
        assert self.auth.auth_method == "token"
        assert self.auth.token_expiry is None
        assert self.auth.authenticated_user == "svc-user"
        assert self.auth.tenant_id == "abc"
        assert self.auth.session.headers["Authorization"] == f"Bearer {self.token}"

    def test_authenticate_with_token_invalid_raises(self):
        self.auth.session.request = MagicMock(
            return_value=make_response(status_code=401, text="Unauthorized")
        )

        with pytest.raises(AuthenticationError):
            self.auth.authenticate_with_token(self.token, url=self.url)

        # State should be cleared on failure
        assert self.auth.token is None
        assert self.auth.auth_method is None
        assert "Authorization" not in self.auth.session.headers

    def test_authenticate_with_token_empty_token_raises(self):
        with pytest.raises(AuthenticationError):
            self.auth.authenticate_with_token("", url=self.url)

    def test_authenticate_prefers_token_over_password(self):
        self.auth.session.request = MagicMock(
            return_value=make_response(status_code=200, json_data={"username": "svc-user"})
        )
        self.auth.session.post = MagicMock()

        result = self.auth.authenticate(
            username="someuser", password="somepass", token=self.token, url=self.url
        )

        assert result is True
        assert self.auth.auth_method == "token"
        # The username/password login endpoint should never be hit
        self.auth.session.post.assert_not_called()


class TestTokenConnectionErrors:
    """Network/TLS failures must not be reported as a bad token."""

    def setup_method(self):
        self.auth = AuthHandler(use_cache=False)
        self.url = "https://10.100.25.136"
        self.token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test"

    def _assert_not_token_error(self, exc_info):
        message = str(exc_info.value)
        assert "expired bearer token" not in message
        assert "not a token problem" in message
        assert self.auth.token is None
        assert self.auth.auth_method is None
        assert "Authorization" not in self.auth.session.headers

    def test_ssl_eof_reports_tls_handshake_problem(self):
        self.auth.session.request = MagicMock(
            side_effect=requests.exceptions.SSLError(
                "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol"
            )
        )

        with pytest.raises(AuthenticationError, match="TLS handshake") as exc_info:
            self.auth.authenticate_with_token(self.token, url=self.url)

        self._assert_not_token_error(exc_info)
        assert "hostname" in str(exc_info.value)

    def test_cert_verify_failure_suggests_ca_bundle(self):
        self.auth.session.request = MagicMock(
            side_effect=requests.exceptions.SSLError(
                "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"
            )
        )

        with pytest.raises(AuthenticationError, match="--ca-bundle") as exc_info:
            self.auth.authenticate_with_token(self.token, url=self.url)

        self._assert_not_token_error(exc_info)

    def test_connection_error_reports_network_problem(self):
        self.auth.session.request = MagicMock(
            side_effect=requests.exceptions.ConnectionError("Connection refused")
        )

        with pytest.raises(AuthenticationError, match="Could not connect") as exc_info:
            self.auth.authenticate_with_token(self.token, url=self.url)

        self._assert_not_token_error(exc_info)

    def test_401_still_reports_invalid_token(self):
        self.auth.session.request = MagicMock(
            return_value=make_response(status_code=401, text="Unauthorized")
        )

        with pytest.raises(AuthenticationError, match="Invalid or expired bearer token"):
            self.auth.authenticate_with_token(self.token, url=self.url)

    def test_requests_use_supplied_url_not_config_url(self):
        self.auth.session.request = MagicMock(
            return_value=make_response(status_code=200, json_data={"username": "svc"})
        )

        self.auth.authenticate_with_token(self.token, url="https://plextrac.internal/")

        called_url = self.auth.session.request.call_args[0][1]
        assert called_url == "https://plextrac.internal/api/v2/whoami"


class TestTlsVerificationConfig:
    """TLS verification settings are applied to the HTTP session."""

    def _handler_with(self, verify_ssl=True, ca_bundle=None):
        from src.auth import auth_handler as module

        config = module.get_config().model_copy(deep=True)
        config.plextrac.verify_ssl = verify_ssl
        config.plextrac.ca_bundle = ca_bundle
        with patch.object(module, "get_config", return_value=config):
            return AuthHandler(use_cache=False)

    def test_verification_enabled_by_default(self):
        assert self._handler_with().session.verify is True

    def test_insecure_disables_verification(self):
        assert self._handler_with(verify_ssl=False).session.verify is False

    def test_ca_bundle_takes_precedence(self):
        handler = self._handler_with(verify_ssl=False, ca_bundle="/etc/ssl/internal-ca.pem")
        assert handler.session.verify == "/etc/ssl/internal-ca.pem"


class TestTokenModeAuthenticationState:
    """Test cases for is_authenticated/ensure_authenticated in token mode."""

    def setup_method(self):
        self.auth = AuthHandler(use_cache=False)

    def test_is_authenticated_true_without_expiry(self):
        self.auth.token = "some-token"
        self.auth.auth_method = "token"
        self.auth.token_expiry = None

        assert self.auth.is_authenticated() is True

    def test_is_authenticated_false_when_token_missing(self):
        self.auth.token = None
        self.auth.auth_method = "token"

        assert self.auth.is_authenticated() is False

    def test_ensure_authenticated_raises_clear_error_for_invalid_token(self):
        self.auth.token = None
        self.auth.auth_method = "token"

        with pytest.raises(AuthenticationError, match="Bearer token"):
            self.auth.ensure_authenticated()

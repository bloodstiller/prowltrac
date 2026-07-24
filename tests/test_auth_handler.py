"""
Tests for bearer token authentication in AuthHandler.
"""

from unittest.mock import MagicMock

import pytest

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

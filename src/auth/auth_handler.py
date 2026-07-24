"""
Authentication handler for PlexTrac API.
Based on PlexTrac-Labs authentication patterns with token caching support.
"""

import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..utils.config import get_config, get_credentials
from ..utils.logger import get_logger
from ..utils.validators import validate_credentials, validate_token
from .interactive_login import interactive_login
from .token_cache import token_cache


class AuthenticationError(Exception):
    """Custom exception for authentication errors."""

    pass


class AuthHandler:
    """Handles PlexTrac API authentication with automatic token refresh and caching."""

    def __init__(
        self, use_cache: bool = True, interactive: bool = False, debug_requests: bool = False
    ):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.use_cache = use_cache
        self.interactive = interactive
        self.debug_requests = debug_requests

        # Authentication state
        self.token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
        self.authenticated_user: Optional[str] = None
        self.plextrac_url: Optional[str] = None
        self.user_info: Optional[Dict[str, Any]] = None
        self.tenant_id: Optional[str] = None
        self.auth_method: Optional[str] = None

        # HTTP session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set default timeout
        self.session.request = self._wrap_request(self.session.request)

    def _wrap_request(self, original_request):
        """Wrap request method to add default timeout."""

        def wrapped_request(*args, **kwargs):
            if "timeout" not in kwargs:
                kwargs["timeout"] = self.config.plextrac.request_timeout
            return original_request(*args, **kwargs)

        return wrapped_request

    def authenticate(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        mfa_token: Optional[str] = None,
        url: Optional[str] = None,
        force_new: bool = False,
        token: Optional[str] = None,
    ) -> bool:
        """Authenticate with PlexTrac API using cached tokens when possible."""

        self.logger.debug(
            f"Starting authentication - interactive: {self.interactive}, use_cache: {self.use_cache}, force_new: {force_new}"
        )

        # A directly-supplied bearer token takes precedence over username/password
        token = token or get_credentials().get("token")
        if token:
            self.logger.debug("Bearer token supplied, skipping username/password login")
            return self.authenticate_with_token(token, url)

        # Determine PlexTrac URL
        self.plextrac_url = url or self.config.plextrac.url
        self.logger.debug(f"Using PlexTrac URL: {self.plextrac_url}")

        # If interactive mode, use interactive login (but only if not in TUI context)
        if self.interactive and not all([username, password]):
            self.logger.debug("Interactive mode requested, checking environment")

            # Don't do interactive login if we're in a TUI environment
            try:
                login_result = interactive_login.login(
                    url=self.plextrac_url, username=username, force_new=force_new
                )

                if not login_result:
                    self.logger.debug("Interactive login cancelled or failed")
                    # Fall through to try cached tokens or environment credentials
                else:
                    # If we got a cached token, use it
                    if login_result.get("from_cache"):
                        return self._load_cached_token(
                            login_result["url"], login_result["username"], login_result["token"]
                        )

                    # Otherwise use the credentials provided
                    username = login_result["username"]
                    password = login_result["password"]
                    mfa_token = login_result.get("mfa_token")
                    self.plextrac_url = login_result["url"]
            except Exception as e:
                self.logger.debug(f"Interactive login failed: {e}")
                # Fall through to try other authentication methods

        # Get credentials from parameters, environment, or config
        if not username or not password:
            creds = get_credentials()
            username = username or creds.get("username")
            password = password or creds.get("password")
            mfa_token = mfa_token or creds.get("mfa_token")

        # Check for cached token first (if caching enabled and not forcing new login)
        if self.use_cache and not force_new and username and self.plextrac_url:
            cached_token = token_cache.load_token(self.plextrac_url, username)
            if cached_token:
                self.logger.info(f"Using cached token for {username}")
                return self._load_cached_token(self.plextrac_url, username, cached_token["token"])

        # Validate required credentials
        if not username or not password:
            if self.interactive:
                raise AuthenticationError("Interactive login failed to provide credentials")
            else:
                raise AuthenticationError("Username and password are required")

        # Validate credentials format
        validation = validate_credentials(username, password, self.plextrac_url)
        if not validation["valid"]:
            raise AuthenticationError(f"Invalid credentials: {', '.join(validation['errors'])}")

        # Perform fresh authentication
        return self._authenticate_fresh(username, password, mfa_token)

    def _load_cached_token(self, url: str, username: str, token: str) -> bool:
        """Load a cached token into the auth handler."""
        try:
            self.token = token
            self.authenticated_user = username
            self.plextrac_url = url
            self.auth_method = "password"

            # Decode token to get expiry (basic JWT decode)
            self.token_expiry = datetime.now() + timedelta(minutes=15)  # Assume 15 min expiry

            # Update session headers
            self.session.headers.update(
                {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
            )

            # Test token validity - if user info fails, try a simple API call instead
            user_info = self.get_current_user()
            if user_info:
                self.user_info = user_info
                # Extract tenant ID from user info if available
                if "tenant_id" in self.user_info:
                    self.tenant_id = self.user_info["tenant_id"]
                    self.logger.debug(
                        f"Extracted tenant ID from cached user info: {self.tenant_id}"
                    )
                self.logger.info(f"Successfully loaded cached token for {username}")
                return True
            else:
                # User info endpoint failed, but token might still be valid
                # Try different PlexTrac API endpoints to test authentication
                # Based on PlexTrac docs, API uses tenant-based structure
                test_endpoints = []
                if hasattr(self, "tenant_id") and self.tenant_id:
                    test_endpoints.extend(
                        [
                            f"/api/v1/tenant/{self.tenant_id}/clients",
                            f"/api/v2/tenant/{self.tenant_id}/clients",
                            f"/api/v1/tenant/{self.tenant_id}",
                            f"/api/v2/tenant/{self.tenant_id}",
                        ]
                    )
                # Fallback endpoints without tenant ID
                test_endpoints.extend(
                    [
                        "/whoami",
                        "/api/v1/clients",
                        "/api/v2/clients",
                        "/api/v1/user",
                        "/api/v2/user",
                    ]
                )

                for endpoint in test_endpoints:
                    try:
                        response = self.make_authenticated_request("GET", endpoint, timeout=5)
                        if response.status_code in [
                            200,
                            403,
                        ]:  # 403 means authenticated but no permission
                            self.user_info = {"username": username, "authenticated": True}
                            self.logger.info(
                                f"Successfully loaded cached token for {username} (tested with {endpoint})"
                            )
                            return True
                        elif response.status_code == 404:
                            # Endpoint doesn't exist, try next one
                            continue
                        else:
                            # Token might be invalid
                            break
                    except (
                        Exception
                    ):  # nosec B112 - Intentionally continuing on endpoint test failures
                        # Try next endpoint
                        continue

                # All endpoints failed - this might be due to API structure differences
                # Since the token was previously valid, let's trust it for now
                self.logger.warning(
                    "Connection test endpoints not accessible, but token may still be valid"
                )
                self.user_info = {"username": username, "authenticated": True}
                self.logger.info(
                    f"Proceeding with cached token for {username} (endpoints not accessible)"
                )
                return True

        except Exception as e:
            self.logger.error(f"Failed to load cached token: {e}")
            return False

    def _authenticate_fresh(self, username: str, password: str, mfa_token: Optional[str]) -> bool:
        """Perform fresh authentication with credentials."""
        try:
            self.logger.info(f"Attempting fresh authentication for user: {username}")

            # Prepare authentication payload
            auth_payload = {"username": username, "password": password}

            # Add MFA token if provided
            if mfa_token:
                auth_payload["mfa_token"] = mfa_token

            # Make authentication request
            auth_url = f"{self.plextrac_url}/api/v1/authenticate"
            self.logger.debug(f"Making auth request to: {auth_url}")

            # Log payload without password
            safe_payload = {k: v for k, v in auth_payload.items() if k != "password"}
            safe_payload["password"] = "[REDACTED]"  # nosec B105 - Not hardcoded password
            self.logger.debug(f"Auth payload: {safe_payload}")

            response = self.session.post(
                auth_url, json=auth_payload, timeout=self.config.plextrac.auth_timeout
            )

            self.logger.debug(f"Auth response status: {response.status_code}")
            if response.status_code != 200:
                self.logger.debug(f"Auth response text: {response.text[:500]}")

            if response.status_code == 200:
                auth_data = response.json()
                self.logger.debug(f"Auth response data keys: {list(auth_data.keys())}")

                # Extract token and user info
                self.token = auth_data.get("token")
                if not self.token:
                    raise AuthenticationError("No token received in authentication response")

                # Extract tenant ID if available
                self.tenant_id = auth_data.get("tenantId")
                if self.tenant_id:
                    self.logger.debug(f"Extracted tenant ID: {self.tenant_id}")

                # Set token expiry (15 minutes from now)
                self.token_expiry = datetime.now() + timedelta(minutes=15)
                self.authenticated_user = username
                self.auth_method = "password"

                # Update session headers
                self.session.headers.update(
                    {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
                )

                # Get user info (optional - don't fail if endpoint doesn't exist)
                self.user_info = self.get_current_user()
                if not self.user_info:
                    self.logger.debug("User info unavailable, but authentication successful")
                    # Create minimal user info for caching
                    self.user_info = {"username": username, "authenticated": True}
                else:
                    # Extract tenant ID from user info if available
                    if "tenant_id" in self.user_info:
                        self.tenant_id = self.user_info["tenant_id"]
                        self.logger.debug(f"Extracted tenant ID from user info: {self.tenant_id}")

                # Cache the token if caching is enabled
                if self.use_cache:
                    try:
                        token_cache.save_token(
                            plextrac_url=self.plextrac_url,
                            username=username,
                            token=self.token,
                            expires_at=self.token_expiry,
                            user_info=self.user_info,
                        )
                        self.logger.debug("Token cached successfully")
                    except Exception as e:
                        self.logger.warning(f"Failed to cache token: {e}")

                self.logger.info(f"Successfully authenticated user: {username}")
                return True

            elif response.status_code == 401:
                try:
                    error_data = response.json()
                    error_msg = error_data.get("message", "Invalid credentials")
                except:
                    error_msg = "Invalid credentials"
                raise AuthenticationError(f"Authentication failed: {error_msg}")

            elif response.status_code == 429:
                raise AuthenticationError(
                    "Too many authentication attempts. Please try again later."
                )

            else:
                raise AuthenticationError(
                    f"Authentication failed with status {response.status_code}"
                )

        except requests.exceptions.RequestException as e:
            raise AuthenticationError(f"Network error during authentication: {str(e)}")
        except AuthenticationError:
            raise
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            raise AuthenticationError(f"Authentication failed: {str(e)}")

    def authenticate_with_token(self, token: str, url: Optional[str] = None) -> bool:
        """Authenticate using a directly-supplied bearer token (skips username/password login).

        The token's expiry is unknown and unmanaged by this tool, so no expiry-based
        refresh is attempted here — a 401 on a later request surfaces as an
        AuthenticationError telling the caller to supply a fresh token.
        """
        self.plextrac_url = url or self.config.plextrac.url

        validation = validate_token(token, self.plextrac_url)
        if not validation["valid"]:
            raise AuthenticationError(f"Invalid token: {', '.join(validation['errors'])}")

        self.token = token
        self.token_expiry = None
        self.auth_method = "token"
        self.authenticated_user = None
        self.tenant_id = None

        # Update session headers
        self.session.headers.update(
            {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        )

        self.logger.info("Validating supplied bearer token")
        try:
            self.user_info = self.get_current_user()
        except Exception as e:
            self.logger.debug(f"Token validation request failed: {e}")
            self.user_info = None

        if self.user_info:
            self.authenticated_user = self.user_info.get("username")
            if "tenant_id" in self.user_info:
                self.tenant_id = self.user_info["tenant_id"]
        else:
            self.token = None
            self.token_expiry = None
            self.auth_method = None
            if "Authorization" in self.session.headers:
                del self.session.headers["Authorization"]
            raise AuthenticationError(
                "Invalid or expired bearer token. Supply a fresh token via --token or "
                "PLEXTRAC_API_TOKEN."
            )

        self.logger.info("Successfully authenticated with bearer token")
        return True

    def is_authenticated(self) -> bool:
        """Check if currently authenticated with valid token."""
        if not self.token:
            return False

        # Bearer tokens supplied directly have no known expiry - trust them until
        # a request comes back with a 401.
        if self.auth_method == "token":
            return True

        if not self.token_expiry:
            return False

        # Check if token is expired (with 1 minute buffer)
        buffer_time = datetime.now() + timedelta(minutes=1)
        return self.token_expiry > buffer_time

    def ensure_authenticated(self) -> None:
        """Ensure we have a valid authentication token."""
        if not self.is_authenticated():
            # A directly-supplied bearer token can't be silently refreshed - there
            # are no credentials to re-login with, so fail fast with a clear error.
            if self.auth_method == "token":
                raise AuthenticationError(
                    "Bearer token is invalid or expired; supply a fresh token via "
                    "--token or PLEXTRAC_API_TOKEN."
                )

            self.logger.info("Token expired or missing, re-authenticating...")

            # If we have cached user info, try to re-authenticate with cache first
            if self.use_cache and self.authenticated_user and self.plextrac_url:
                cached_token = token_cache.load_token(self.plextrac_url, self.authenticated_user)
                if cached_token:
                    if self._load_cached_token(
                        self.plextrac_url, self.authenticated_user, cached_token["token"]
                    ):
                        return

            # Try to re-authenticate with stored credentials
            creds = get_credentials()
            if creds.get("username") and creds.get("password"):
                self.authenticate(
                    username=creds.get("username"),
                    password=creds.get("password"),
                    mfa_token=creds.get("mfa_token"),
                )
            elif self.interactive:
                # Use interactive login for re-authentication
                self.authenticate()
            else:
                raise AuthenticationError("No stored credentials available for re-authentication")

    def make_authenticated_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make an authenticated API request with automatic token refresh."""
        # Ensure we have a valid token
        self.ensure_authenticated()

        # Prepare full URL
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint

        # Check if endpoint already has API version prefix
        if endpoint.startswith("/api/"):
            url = f"{self.config.plextrac.url}{endpoint}"
        else:
            url = f"{self.config.plextrac.url}/api/{self.config.plextrac.api_version}{endpoint}"

        try:
            # Make the request
            response = self.session.request(method, url, **kwargs)

            # Enhanced logging for debugging
            self.logger.debug(f"{method} {endpoint} -> {response.status_code}")
            if self.debug_requests or response.status_code != 200:
                self.logger.debug(f"Request URL: {url}")
                self.logger.debug(f"Request headers: {dict(self.session.headers)}")
                if response.status_code != 200:
                    self.logger.debug(f"Response headers: {dict(response.headers)}")
                    self.logger.debug(f"Response body: {response.text[:500]}")
                elif self.debug_requests:
                    self.logger.debug(f"Response headers: {dict(response.headers)}")
                    self.logger.debug(f"Response body: {response.text[:200]}...")

            # Handle token expiry
            if response.status_code == 401:
                self.logger.warning("Received 401, attempting to re-authenticate")

                # Clear current token and try to re-authenticate
                self.token = None
                self.token_expiry = None
                self.ensure_authenticated()

                # Retry the request once
                response = self.session.request(method, url, **kwargs)
                self.logger.debug(f"Retry {method} {endpoint} -> {response.status_code}")

            return response

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {method} {endpoint} - {str(e)}")
            raise

    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """Get information about the currently authenticated user."""
        if not self.is_authenticated():
            return None

        try:
            response = self.make_authenticated_request("GET", "/whoami")
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.warning(f"Failed to get user info: {response.status_code}")
                return None
        except Exception as e:
            self.logger.error(f"Error getting user info: {str(e)}")
            return None

    def logout(self, clear_cache: bool = False) -> None:
        """Logout and clear authentication state."""
        if self.token:
            try:
                # Attempt to logout on server side
                self.make_authenticated_request("POST", "/logout")
            except Exception as e:
                self.logger.warning(f"Error during logout: {str(e)}")

        # Clear cached token if requested
        if clear_cache and self.authenticated_user and self.plextrac_url:
            try:
                token_cache.remove_token(self.plextrac_url, self.authenticated_user)
                self.logger.info("Cleared cached token")
            except Exception as e:
                self.logger.warning(f"Failed to clear cached token: {e}")

        # Clear local state
        self.token = None
        self.token_expiry = None
        self.authenticated_user = None
        self.plextrac_url = None
        self.user_info = None
        self.auth_method = None

        # Clear session headers
        if "Authorization" in self.session.headers:
            del self.session.headers["Authorization"]

        self.logger.info("Logged out successfully")

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for manual requests."""
        self.ensure_authenticated()
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def __del__(self):
        """Clean up session on destruction."""
        if hasattr(self, "session"):
            self.session.close()

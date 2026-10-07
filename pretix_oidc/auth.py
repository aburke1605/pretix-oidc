import logging
import time
from urllib.parse import urlsplit
from django.urls import reverse
from oic import rndstr
from oic.oic import Client
from oic.oic.message import (
    AuthorizationResponse,
    ProviderConfigurationResponse,
    RegistrationResponse,
)
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from pretix.base.auth import BaseAuthBackend
from pretix.settings import config

logger = logging.getLogger(__name__)

# begin MITO custom
def _validated_next_url(next_url):
    """
    Return a safe local redirect target or the Pretix control landing page.

    Accepted:
        /control/
        /control/event/mito/example/
        /control/?page=2

    Rejected:
        https://attacker.example/
        //attacker.example/
        javascript:alert(1)
        control/
        backslash-based variants
        control characters
    """
    fallback = reverse("control:index")

    if not next_url or not isinstance(next_url, str):
        return fallback

    # keep the limit conservative to avoid abnormal redirect values
    if len(next_url) > 2048:
        return fallback

    # reject control characters, including CR/LF header-injection attempts
    if any(ord(character) < 32 or ord(character) == 127 for character in next_url):
        return fallback

    # browsers and proxies can interpret backslashes inconsistently
    if "\\" in next_url:
        return fallback

    try:
        parsed = urlsplit(next_url)
    except ValueError:
        return fallback

    # require a relative URL without a scheme or network location
    if parsed.scheme or parsed.netloc:
        return fallback

    # require an absolute path on the current origin
    if not parsed.path.startswith("/"):
        return fallback

    # a path beginning with // can be interpreted as scheme-relative
    if parsed.path.startswith("//"):
        return fallback

    # restrict redirects to the Pretix backend
    if not (
        parsed.path == "/control"
        or parsed.path.startswith("/control/")
    ):
        return fallback

    return next_url
# end MITO custom

class OIDCAuthBackend(BaseAuthBackend):
    def __init__(self):
        try:
            self.title = config.get(
                "oidc", "title", fallback="Login with OpenID connect"
            )

            op_info = ProviderConfigurationResponse(
                version="1.0",
                issuer=config.get("oidc", "issuer"),
                authorization_endpoint=config.get("oidc", "authorization_endpoint"),
                token_endpoint=config.get("oidc", "token_endpoint"),
                userinfo_endpoint=config.get("oidc", "userinfo_endpoint"),
                end_session_endpoint=config.get("oidc", "end_session_endpoint"),
                jwks_uri=config.get("oidc", "jwks_uri"),
            )

            client_reg = RegistrationResponse(
                client_id=config.get("oidc", "client_id"),
                client_secret=config.get("oidc", "client_secret"),
            )

            self.client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
            self.client.handle_provider_config(op_info, op_info["issuer"])
            self.client.store_registration_info(client_reg)
            self.client.redirect_uris = [None]

            self.scopes = config.get("oidc", "scopes", fallback="openid").split(",")
        except KeyError:
            logger.error(
                "Please specify issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, end_session_endpoint, jwks_uri, client_id and client_secret "
                "in [oidc] section in pretix.cfg"
            )

    @property
    def identifier(self):
        return "pretix_oidc"

    @property
    def verbose_name(self):
        return self.title

    def authentication_url(self, request):
        oidc_state = rndstr()

        # begin MITO custom
        oidc_nonce = rndstr()
        next_url = _validated_next_url(request.GET.get("next", None))
        # end MITO custom

        request.session["oidc_state"] = {
            oidc_state: {
                "next": next_url, # MITO custom
                "nonce": oidc_nonce, # MITO custom
                "generated_on": int(time.time()),
            }
        }

        auth_req = self.client.construct_AuthorizationRequest(
            request_args={
                "client_id": self.client.client_id,
                "response_type": "code",
                "scope": self.scopes,
                "redirect_uri": self.redirect_uri(request),
                "state": oidc_state,
                "nonce": oidc_nonce, # MITO custom
            }
        )

        return auth_req.request(self.client.authorization_endpoint)

    def redirect_uri(self, request):
        return request.build_absolute_uri(reverse("plugins:pretix_oidc:oidc_callback"))

    def get_next_url(self, request):
        next_url = request.session.pop("oidc_next_url", None)
        return _validated_next_url(next_url)

    def process_callback(self, request):
        auth_response = self.client.parse_response(
            AuthorizationResponse,
            info=request.META["QUERY_STRING"],
            sformat="urlencoded",
        )

        request.session["oidc_next_url"] = None
        oidc_state = request.session.pop("oidc_state", None)
        response_state = auth_response.get("state", None)

        if not oidc_state or not response_state:
            return [None, None]

        if response_state not in oidc_state:
            return [None, None]

        if oidc_state[response_state]["generated_on"] < time.time() - 5 * 60:
            return [None, None]

        # begin MITO custom
        expected_nonce = oidc_state[response_state]["nonce"]
        if not expected_nonce:
            logger.warning("OIDC callback session does not contain a nonce")
            return [None, None]

        request.session["oidc_next_url"] = _validated_next_url(oidc_state[response_state]["next"])
        # end MITO custom

        access_token_response = self.client.do_access_token_request(
            state=auth_response["state"],
            scope=self.scopes,
            request_args={
                "code": auth_response["code"],
                "redirect_uri": self.redirect_uri(request),
            },
            authn_method="client_secret_basic",
        )

        userinfo = self.client.do_user_info_request(state=auth_response["state"])

        id_token = access_token_response["id_token"]

        # begin MITO custom
        if id_token.get("nonce") != expected_nonce:
            logger.warning("OIDC ID token nonce does not match the login request")
            return [None, None]

        if (userinfo["sub"] != id_token["sub"]):
            logger.warning("OIDC UserInfo subject does not match the ID token subject")
            return [None, None]
        # end MITO custom

        user_data = {
            "uuid": userinfo[config.get("oidc", "unique_attribute", fallback="sub")],
            "email": userinfo["email"],
            "fullname": userinfo["name"],
            "auth_backend": self.identifier,
        }

        return [user_data, id_token]

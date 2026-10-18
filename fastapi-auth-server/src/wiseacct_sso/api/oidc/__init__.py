"""Isolated HTTP surface for the FastAPI-native OIDC provider."""

from wiseacct_sso.api.oidc.app import OidcHttpService, build_oidc_app

__all__ = ["OidcHttpService", "build_oidc_app"]

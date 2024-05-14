import os
import requests
from radicale.auth import BaseAuth
from typing import Tuple, Union
from radicale import types
from radicale.log import logger

PLUGIN_CONFIG_SCHEMA = {"auth": {
    "wildduck_api_url": {"value": "", "type": str},
    "wildduck_api_token": {"value": "", "type": str}}}

class Auth(BaseAuth):
    def __init__(self, configuration):
        super().__init__(configuration)
        self.wildduck_api_url = self.configuration.get("auth", "wildduck_api_url")
        self.wildduck_api_token = self.configuration.get("auth", "wildduck_api_token")

    def get_external_login(self, environ: types.WSGIEnviron) -> Union[Tuple[()], Tuple[str, str]]:
        self._environ = environ
        x_access_token = environ.get("HTTP_X_ACCESS_TOKEN")
        x_target_user = environ.get("HTTP_X_TARGET_USER")

        if x_access_token:
            authenticated_user = self._authenticate_with_token(x_access_token, x_target_user)
            if authenticated_user:
                return authenticated_user, ""

        return None

    def login(self, login: str, password: str) -> str:
        #logger.debug("Login method called with login: '%s' and password: '%s'", login, password)
        x_access_token = self._environ.get("HTTP_X_ACCESS_TOKEN")
        x_target_user = self._environ.get("HTTP_X_TARGET_USER")

        if x_access_token:
            authenticated_user = self._authenticate_with_token(x_access_token, x_target_user)
            if authenticated_user:
                self._environ["REMOTE_USER"] = authenticated_user
                return authenticated_user

        if login and password:
            authenticated_user = self._authenticate_with_password(login, password)
            if authenticated_user:
                self._environ["REMOTE_USER"] = authenticated_user
                return authenticated_user

        return ()

    def _authenticate_with_password(self, user, password):
        #logger.debug("Login attempt by '%s' with password.", user)
        headers = {"X-Access-Token": self.wildduck_api_token}
        try:
            response = requests.post(f"{self.wildduck_api_url}/authenticate", headers=headers, json={
                "username": user,
                "password": password,
            })

            response.raise_for_status()

            if response.json()["success"]:
                logger.info("User '%s' authenticated successfully with password.", user)
                return user

        except requests.RequestException as e:
            logger.error("Error authenticating with WildDuck: %s", e)
            return False

    def _authenticate_with_token(self, x_access_token, x_target_user):
        #logger.debug("Login attempt with token - '%s'.", x_access_token)

        # Validate the supplied token if the target user is specified
        if x_target_user:
            #logger.debug("Pre-auth check for target user - '%s' with supplied token.", x_target_user)
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {x_access_token}"
            }
            preauth_response = requests.post(
                f"{self.wildduck_api_url}/users/{x_target_user}/preauth",
                headers=headers,
                json={"username": x_target_user}
            )
            
            if preauth_response.status_code == 200 and preauth_response.json().get("success"):
                logger.info("Pre-auth check succeeded for target user '%s'.", x_target_user)
                return x_target_user
            else:
                logger.warning("Pre-auth check failed for target user '%s'.", x_target_user)
                return False

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.wildduck_api_token}",
            "X-Access-Token": x_access_token
        }

        response = requests.get(f"{self.wildduck_api_url}/users/me", headers=headers)
        user_data = response.json()

        if response.status_code == 200 and user_data.get("success"):
            user_id = user_data["id"]
            username = user_data["username"]
            logger.info("User with ID '%s' authenticated successfully with token.", user_id)
            return username

        logger.warning("Authentication failed with token.")
        return False

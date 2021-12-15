import json

from flask import request
from os import environ
import requests


class PermissionsManager:
    ENABLE_COMPLII = "ENABLE_COMPLII"
    COMPLII_URL = "COMPLII_URL"
    SEPARATOR = "/"
    PERMISSIONS_API_URL_PATH = "complii/api/permissions"
    COMPANY_NAME = "ORGANISATION_NAME"

    BLOTOUT_USER_EMAIL = "bo_email"
    BLOTOUT_USER_TOKEN = "bo_token"

    def __init__(self) -> None:
        self._complii_enabled = True if (environ.get(self.ENABLE_COMPLII) == 1) || (environ.get(self.ENABLE_COMPLII) == '1') else False
        self._client = requests
        self._url = "{0}{1}{2}".format(environ.get(self.COMPLII_URL), self.SEPARATOR,
                                       self.PERMISSIONS_API_URL_PATH)
        self._company = environ.get(self.COMPANY_NAME)
        self._group = request.headers.get(self.BLOTOUT_USER_EMAIL)
        self._token = request.headers.get(self.BLOTOUT_USER_TOKEN)

    # TODO: Testing is pending for this function post header changes
    def check_for_sql(self, query) -> (bool, str):

        if not self._complii_enabled:
            return True, "Complii Disabled"

        query_type = "sql"

        headers = {
            "Content-Type": "application/json",
            "Authorization": "token " + self._token
        }
        data = {
            "companyName": self._company,
            "groupId": self._group,
            "queryType": query_type,
            "sql": query
        }
        response = requests.post(self._url, json=data, headers=headers)
        res = json.loads(response.text)

        if response.status_code == 200:
            message = None
            if not res["allowQuery"]:
                cols = [item["name"] for item in res["objects"] if
                        item["state"] == "DENIED"]
                message = "Permission Denied for " + ", ".join(cols)
            return res["allowQuery"], message
        else:
            return False, res["message"]

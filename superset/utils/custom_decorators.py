import json
from functools import wraps
from flask import request, Response
from werkzeug.exceptions import abort

from superset.utils.permissions_manager import PermissionsManager


def authenticate_permissions_request(is_sql_query=False, is_json_query=False):

    def wrap(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            def check_sql_permission(sql):
                permissions = PermissionsManager()
                return permissions.check_for_sql(sql)

            if is_sql_query:
                sql = request.json['sql']
                res = check_sql_permission(sql)
                if not res[0]:
                    return abort(401, res[1])
            
            if is_json_query:
                json_resp = fn(*args, **kwargs)
                if json_resp:
                    # '\n' in response causes exception during parsing. So replacing new line escape sequence
                    json_resp.replace("\n", " ")
                    resp = json.loads(json_resp)
                    for cacheObj in resp["result"]:
                        sql = cacheObj["query"]
                        res = check_sql_permission(sql)
                        if not res[0]:
                            return abort(401, res[1])

            return fn(*args, **kwargs)

        return wrapper

    return wrap
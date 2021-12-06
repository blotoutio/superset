import json
from functools import wraps
from flask import request
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
            
            def check_json_query(result_obj):
                sql = result_obj["query"]
                return check_sql_permission(sql)


            if is_json_query:
                resp = fn(*args, **kwargs)
                if resp.status_code == 200:
                    result_list = None
                    resp_obj = json.loads(resp.response[0])
                    try:
                        result_list = resp_obj["result"]
                    except KeyError:
                        res = check_json_query(resp_obj)
                        if not res[0]:
                            return abort(401, res[1])
                    if result_list is not None:
                        for result in result_list:
                            res = check_json_query(result)
                            if not res[0]:
                                return abort(401, res[1])

            return fn(*args, **kwargs)

        return wrapper

    return wrap
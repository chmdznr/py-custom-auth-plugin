import json
import os
import sys
from tyk.decorators import *
from gateway import TykGateway as tyk
import traceback

# from time import time

# Add vendor directory to module search path
parent_dir = os.path.abspath(os.path.dirname(__file__))
vendor_dir = os.path.join(parent_dir, 'vendor')

sys.path.append(vendor_dir)

import jwt


@Hook
def auth_check_2022012802(request, session, metadata, spec):
    tyk.log("AuthCheck is called", "info")
    tyk.log("hello world", "info")
    tyk.log(spec["config_data"], "info")
    spec_obj = json.loads(spec["config_data"])
    # endpoint = spec_obj["endpoint"]
    # tyk.log(endpoint, "info")
    # tyk.log(spec_obj, "info")

    # tyk.log(request, "info")
    # public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAltnb4lSe2Y9ia8vfep3pW7mgXb1U8oIs9pVJTiZp0P5xNaPjLAwo2yDpNY4pb4HLndfKBvDvh2e7CYa/BttN+mrd/CKuu8YRi1JeMdt2VMEP45o5xQ5aoP0TWVaQMJIIt+rXgLi/6DPS6HWmooHcj/X36FPpDJSDcvisp3Pr7fCpWoK295lsgVQUFMfDh+HRGPTkWCAC1Qu34SaoIAVDlLfrhCMC6yU48dORt2+8mZZcuRpJyjnJs/epuRpH0MlsNAefWccdSbA37PtPitXbWzGNjvo2W/LNkvz1zorOvoIHNZh1O2OKBdh+v5dhXFlkfMPU4yYoyr4BMGGwzQKgtwIDAQAB\n-----END PUBLIC KEY-----"
    # tyk.log(type(public_key), "info")
    public_key = ""  # empty just for init
    # tyk.log(public_key, "info")

    # request.get_header is a helper method, to get the full header list, use request.object.headers
    auth_header = request.get_header("Authorization")
    # tyk.log(auth_header, "info")
    auth_token = auth_header.split(" ", 1)[-1].strip()
    # tyk.log(type(auth_token), "info")
    tyk.log(auth_token, "info")
    try:
        jwt_headers = jwt.get_unverified_header(auth_token)
        # tyk.log("hasil jwt headers", "info")
        # tyk.log(jwt_headers, "info")

        unverified_token = jwt.decode(auth_token, options={"verify_signature": False})
        # tyk.log("hasil unverified token", "info")
        # tyk.log(unverified_token, "info")
        print(unverified_token)
        oidc_jwt_azp = ""
        if "azp" in unverified_token:
            oidc_jwt_azp = unverified_token["azp"]

        tyk.log(oidc_jwt_azp, "info")

        # get public key for this Oidc client
        pk = ""
        for ac in spec_obj["allowed_clients"]:
            tyk.log(ac["name"], "info")
            if ac["name"] == oidc_jwt_azp:
                pk = "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----".format(ac["public_key"])
        tyk.log(pk, "info")
        public_key = bytes(pk, 'utf-8')
    except Exception as e:
        tyk.log("AuthCheck is failed #1", "error")
        tyk.log(traceback.format_exc(), "error")
        # Set a custom error:
        # request.object.return_overrides.response_error = repr(e)
        request.object.return_overrides.override_error = True
        request.object.return_overrides.response_body = json.dumps(
            {"error": "invalid_login", "error_description": "Invalid token"})
        request.object.return_overrides.response_code = 403
        return request, session, metadata

    try:
        tyk.log("Masuk mulai decode", "info")
        decoded = jwt.decode(auth_token, public_key, audience="account", algorithms=[jwt_headers['alg']],
                             options={"verify_signature": True})
        tyk.log("AuthCheck is successful", "info")
        # print(decoded)
        # tyk.log(decoded, "info")
        # print(type(decoded))
        # print(decoded['name'])
        metadata["token"] = auth_header
        if "sub" in decoded:
            metadata["sub"] = decoded["sub"]
        if "exp" in decoded:
            metadata["exp"] = str(decoded["exp"])
        if "azp" in decoded:
            metadata["azp"] = decoded["azp"]
        return request, session, metadata
    except Exception as e:
        tyk.log("AuthCheck is failed #2", "error")
        tyk.log(traceback.format_exc(), "error")
        # Set a custom error:
        # request.object.return_overrides.response_error = repr(e)
        request.object.return_overrides.override_error = True
        request.object.return_overrides.response_body = json.dumps(
            {"error": "invalid_login", "error_description": "Invalid token"})
        request.object.return_overrides.response_code = 403
        return request, session, metadata

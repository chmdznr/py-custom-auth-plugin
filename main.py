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


def logic_test(public_key, token):
    jwt_headers = jwt.get_unverified_header(token)
    try:
        decoded = jwt.decode(token, public_key, audience="account", algorithms=[jwt_headers['alg']],
                             options={"verify_signature": True})
        print(decoded)
        print(type(decoded))
        # print(decoded['name'])
    except Exception as e:
        print(traceback.format_exc())


@Hook
def AuthCheck(request, session, metadata, spec):
    tyk.log("AuthCheck is called", "info")
    tyk.log("hello world", "info")
    tyk.log(request, "info")
    public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAltnb4lSe2Y9ia8vfep3pW7mgXb1U8oIs9pVJTiZp0P5xNaPjLAwo2yDpNY4pb4HLndfKBvDvh2e7CYa/BttN+mrd/CKuu8YRi1JeMdt2VMEP45o5xQ5aoP0TWVaQMJIIt+rXgLi/6DPS6HWmooHcj/X36FPpDJSDcvisp3Pr7fCpWoK295lsgVQUFMfDh+HRGPTkWCAC1Qu34SaoIAVDlLfrhCMC6yU48dORt2+8mZZcuRpJyjnJs/epuRpH0MlsNAefWccdSbA37PtPitXbWzGNjvo2W/LNkvz1zorOvoIHNZh1O2OKBdh+v5dhXFlkfMPU4yYoyr4BMGGwzQKgtwIDAQAB\n-----END PUBLIC KEY-----"
    tyk.log(type(public_key), "info")
    tyk.log(public_key, "info")

    # request.get_header is a helper method, to get the full header list, use request.object.headers
    auth_header = request.get_header('Authorization')
    tyk.log(auth_header, "info")
    auth_token = auth_header.split(" ", 1)[-1].strip()
    tyk.log(type(auth_token), "info")
    tyk.log(auth_token, "info")
    try:
        jwt_headers = jwt.get_unverified_header(auth_token)
    except Exception as e:
        tyk.log("AuthCheck is failed #1", "error")
        tyk.log(traceback.format_exc(), "error")
        # Set a custom error:
        request.object.return_overrides.response_error = repr(e)
        request.object.return_overrides.response_code = 403
        return request, session, metadata

    tyk.log("hasil jwt headers", "info")
    tyk.log(jwt_headers, "info")
    try:
        tyk.log("Masuk mulai decode", "info")
        decoded = jwt.decode(auth_token, public_key, audience="account", algorithms=[jwt_headers['alg']],
                             options={"verify_signature": True})
        tyk.log("AuthCheck is successful", "info")
        # print(decoded)
        tyk.log(decoded, "info")
        # print(type(decoded))
        # print(decoded['name'])
        metadata["token"] = auth_header
        metadata["sub"] = decoded["sub"]
        metadata["exp"] = decoded["exp"]
        metadata["azp"] = decoded["azp"]
        return request, session, metadata
    except Exception as e:
        tyk.log("AuthCheck is failed #2", "error")
        tyk.log(traceback.format_exc(), "error")
        # Set a custom error:
        request.object.return_overrides.response_error = repr(e)
        request.object.return_overrides.response_code = 403
        return request, session, metadata


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # samplePublicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6S7asUuzq5Q/3U9rbs+P\nkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb/X\nqZaKgSYaC/h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONY\nW5Zu3PwyvAWk5D6ueIUhLtYzpcB+etoNdL3Ir2746KIy/VUsDwAM7dhrqSK8U2xF\nCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAK\nctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcaj\ntwIDAQAB\n-----END PUBLIC KEY-----"
    # sampleToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTYzNjMyMDI3NCwiZXhwIjoxNjM2MzIzODc0fQ.gSHUZZ9sYbaMOOPn8iwmpu42MKsH3SK2siVEPEv71O2Kt3ouDx88YG43LEC4ycMez1RPyQ0ExQqlZau-Kn1W67g4WkITuFsT7Lhg-k4DAtl-C2rIbqwxhDhXO-DrECfX41PApWdQxSTtE0IPrHG9IxJerjZ5kSlUoW65IfSaHi8pbuDaXBpZt0umMmL9Ym-gNuEowW7weKMuwi9x33MotI4fsN7cyP6uNu5CYtRIIzVzkOxgx2aDyMoHfBi-YOWIuBu3zw_vQkgAM60nDJoujkDkAnxA9c-yeU1LS_g3ImYnKykhdaRwXq7RxxYm9ujlgo_b78hMgovg-Q5Fzr06FQ"
    # sampleToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJIYTVYUnVFUXZmaFhmYzFRZ2RQc3NCN0lETkQ4R3NEZDBQTXpWalhTQTY0In0.eyJleHAiOjE2MzkzNTM4NzQsImlhdCI6MTYzOTM1MDI3NCwianRpIjoiYjk2ZDc5ZTAtMmM5MS00ODJlLTk4ZDctYTgzMzlhYmI3Nzc1IiwiaXNzIjoiaHR0cHM6Ly9zc28tZGV2LmxheWFuYW4uZ28uaWQvYXV0aC9yZWFsbXMvU1BCRSIsImF1ZCI6WyJhcGxpa2FzaS10ZXN0aW5nLWR1YSIsInBzZSIsIm1vbmRpayIsImJhbmtzYW1wYWgiLCJhcGxpa2FzaS1kdWEiLCJzcmlrYW5kaV9kZXYiLCJhY2NvdW50Il0sInN1YiI6IjIwZmIwMDI4LWQxNTctNDM2Mi05ZmIzLTYzMWIyMWE0MWRhZiIsInR5cCI6IkJlYXJlciIsImF6cCI6ImFwbGlrYXNpLXRlc3RpbmciLCJzZXNzaW9uX3N0YXRlIjoiYWY0YTU0YmItNTE2MC00ZDkxLThkOTQtMDkzNzg5YWIxNzAyIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyIqIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsImFrc2VzX2FkbWluIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhcGxpa2FzaS10ZXN0aW5nLWR1YSI6eyJyb2xlcyI6WyJ1c2VyIl19LCJwc2UiOnsicm9sZXMiOlsiQURNSU4iXX0sIm1vbmRpayI6eyJyb2xlcyI6WyJvcGVyYXRvcl9zZWtvbGFoIl19LCJiYW5rc2FtcGFoIjp7InJvbGVzIjpbImFkbWluLWRpbmFzLWtvbWluZm8iXX0sImFwbGlrYXNpLWR1YSI6eyJyb2xlcyI6WyJIVU1BTl9SRVNPVVJDRSJdfSwiYXBsaWthc2ktdGVzdGluZyI6eyJyb2xlcyI6WyJtZW1iZXIiXX0sInNyaWthbmRpX2RldiI6eyJyb2xlcyI6WyI2Il19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJzaWQiOiJhZjRhNTRiYi01MTYwLTRkOTEtOGQ5NC0wOTM3ODlhYjE3MDIiLCJuaWsiOiIxMjM0NTYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmlwIjoiMzQ1IiwibmFtZSI6IkFkbWluIFRlc3RpbmdhbiIsImdyb3VwcyI6WyJvZmZsaW5lX2FjY2VzcyIsImFrc2VzX2FkbWluIiwidW1hX2F1dGhvcml6YXRpb24iXSwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWRtaW4tdGVzdGluZyIsImdpdmVuX25hbWUiOiJBZG1pbiIsImZhbWlseV9uYW1lIjoiVGVzdGluZ2FuIiwiZW1haWwiOiJhZG1pbkB0ZXN0aW5nLmNvbSJ9.SxN6R6fkFoFMAeTXDF2ytgUCSRcrgYDMfCzDPpFlkvkiW0_WE1LCrIgG0d7kgnKWHIiKS8e8-j7cZvUZrT4LCE1qhmWp12A1cDuOcgp_6BPf1InyGVUe7Lr_EqfMd6oTQEA6VF6-8Qq_tE9jlK2vG_1MBGUFrm5xdiVFwWpjnVJrgLRZbl70It_rn8HG51gD1pqPT-wtpf-zqmlRgLTsJeYqPPpVC5fdNL_MU2tdZNRcPeoT4bjfci-D7_nI6jajiSWgCgOMvPJQNhuAI6mtj3-UCj5RCSu9_5T5kBb0cZUxcYz1_4uEHc5V0rs-cStDYPhAy4EwygomNsmy4eXaXg"
    samplePublicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAltnb4lSe2Y9ia8vfep3pW7mgXb1U8oIs9pVJTiZp0P5xNaPjLAwo2yDpNY4pb4HLndfKBvDvh2e7CYa/BttN+mrd/CKuu8YRi1JeMdt2VMEP45o5xQ5aoP0TWVaQMJIIt+rXgLi/6DPS6HWmooHcj/X36FPpDJSDcvisp3Pr7fCpWoK295lsgVQUFMfDh+HRGPTkWCAC1Qu34SaoIAVDlLfrhCMC6yU48dORt2+8mZZcuRpJyjnJs/epuRpH0MlsNAefWccdSbA37PtPitXbWzGNjvo2W/LNkvz1zorOvoIHNZh1O2OKBdh+v5dhXFlkfMPU4yYoyr4BMGGwzQKgtwIDAQAB\n-----END PUBLIC KEY-----"
    sampleToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHakJFMlNFMWtPYVNsU2xDaWNWZkNWcm1PQ1FWUUdJdlBfMHZMQ2lRT2pFIn0.eyJleHAiOjE2Mzk3ODQ5MzMsImlhdCI6MTYzOTcxMjkzMywianRpIjoiZTI5NjYxODktNzYzYi00OTA4LTkzZjMtNTU0YTc0MmZkM2FmIiwiaXNzIjoiaHR0cDovLzEwLjIuMjkuNTI6MjA4MC9hdXRoL3JlYWxtcy9tb2JzZWMiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiYmJmMTI1NDgtOWQxNi00OTJmLWE5MTMtZDUwNGE4YjAxMDllIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYWQxZ2F0ZV9tb2JpbGUiLCJzZXNzaW9uX3N0YXRlIjoiMTI2YWFiMTgtMmU0NC00Mzk3LWJkNjUtYmUxMzA2MzJkY2ZkIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyIqIiwiaHR0cDovL2h0dHBiaW4ub3JnIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1vYnNlYyIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InJlYWQgd3JpdGUiLCJzaWQiOiIxMjZhYWIxOC0yZTQ0LTQzOTctYmQ2NS1iZTEzMDYzMmRjZmQifQ.cMppZyRlGdveJBe8-799jSMLXSu2-jLaLczgEOZuu1WYOTevbdEe2isgXlLVXnYPSPd6KmIMzSTWHm4q11uXpkpoMeLIFl1lRVS8oyTCCOrGbIBZSsclr_7GTgSnB0stVi5qDcILpUoNVeryPm0Qog7ans6HLGQzVN5-WepKIjHJoJpGOqYrdm1aimeLij4DN4pImVaO3IIYuvh3-RI1FuJ0u2dHB1V_31TfQbA85gt6bKoalUxjOWjBwwHHSrUtTWOcW1JG9pY5YJ0rJq_3v85ak2JJL77hAXgjYxuU3vrc04u7f_pHj-v3IRIQ58-NaPO1ggA51TBeiud-aEaCiA"
    # print_hi('PyCharm')
    logic_test(samplePublicKey, sampleToken)

import io
import json
import logging
import jwt
import datetime
from datetime import timedelta
import time
import base64

from fdk import response
import requests
from requests.auth import HTTPBasicAuth
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import ociVault

oauth_apps = {}

def initContext(context):
    if (len(oauth_apps) < 2):
        try:
            logging.getLogger().info("initContext: Initializing context")

            oauth_apps['idcs'] = {'token_endpoint': context['identity_domain_base_url'],
                                'client_id': context['client_id'],
                                'client_secret': ociVault.getSecret(context['secret_ocid'])}
        except Exception as ex:
            logging.getLogger().error("initContext: Failed to get config or secrets" + str(ex))
            raise

def get_encoded(clid, clsecret):
    encoded = clid + ":" + clsecret
    baseencoded = base64.urlsafe_b64encode(encoded.encode('UTF-8')).decode('ascii')
    return baseencoded

def get_access_token(url, header):
    para = "grant_type=client_credentials&scope=urn:opc:idm:__myscopes__"
    response = requests.post(url, headers=header, data=para, verify=True)
    jsonresp = json.loads(response.content)
    access_token = jsonresp.get('access_token')
    return access_token

def printaccesstoken(idcsURL,clientID,clientSecret):
    encodedtoken = get_encoded(clientID, clientSecret)
    extra = "/oauth2/v1/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8','Authorization': 'Basic %s' % encodedtoken, 'Accept': '*/*'}
    accesstoken = get_access_token(idcsURL + extra, headers)
    return accesstoken

def validatescope(token,client_apps):

    access_token_payload = token[len('Bearer '):]
    jwtToken = json.loads(json.dumps(jwt.decode(access_token_payload, options={"verify_signature": False})))

    scope = jwtToken['scope']
    appID = jwtToken['client_guid']

    access_token = printaccesstoken(client_apps['idcs']['token_endpoint'],client_apps['idcs']['client_id'],client_apps['idcs']['client_secret'])
    headers = {'Accept': '*/*', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + access_token}
    resp = requests.get(client_apps['idcs']['token_endpoint'] + "/admin/v1/Apps/" + appID , headers=headers, verify=True)
    jsonresp = json.loads(resp.content)

    new_client_id = jsonresp["name"]
    new_client_secret = jsonresp["clientSecret"]

    for x in jsonresp["allowedScopes"]:
        val = x["fqs"]
        if "consumer::all" in val:
            encodedtoken = get_encoded(new_client_id,new_client_secret)
            extra = "/oauth2/v1/token"
            headers1 = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8','Authorization': 'Basic %s' % encodedtoken, 'Accept': '*/*'}
            para = "grant_type=client_credentials&scope=%s" % val
            response = requests.post(client_apps['idcs']['token_endpoint']+extra, headers=headers1, data=para, verify=True)

            jsonresp1 = json.loads(response.content)
            access_token_new = jsonresp1.get('access_token')

    response = {
        "active": True,
        "scope": scope,
        "context": {
            "token": ('Bearer ' + str(access_token_new))
        }
    }

    context = json.dumps(response, indent=2)
    return response

def handler(ctx, data: io.BytesIO = None):
    initContext(dict(ctx.Config()))

    auth_context = {}
    try:
        logging.getLogger().info("handler: Started Function Execution") 
        gateway_auth = json.loads(data.getvalue())
        token = gateway_auth.get("data", {}).get("token", None)

        auth_context = validatescope(token, oauth_apps)

        if isinstance(auth_context, str):
            auth_context = json.loads(auth_context)

        if auth_context.get("active", False):
            logging.getLogger().info("Authorizer returning 200...")
            return response.Response(
                ctx,
                response_data=json.dumps(auth_context),
                status_code=200,
                headers={"Content-Type": "application/json"}
            )
        else:
            logging.getLogger().info("Authorizer returning 401...")
            return response.Response(
                ctx,
                response_data=json.dumps(auth_context),
                status_code=401,
                headers={"Content-Type": "application/json"}
            )

    except (Exception, ValueError) as ex:
        logging.getLogger().info("error parsing json payload: " + str(ex))
        return response.Response(
            ctx,
            response_data=json.dumps({"error": str(ex)}),
            status_code=500,
            headers={"Content-Type": "application/json"}
        )

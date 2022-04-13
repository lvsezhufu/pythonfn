import logging
import azure.functions as func
import requests
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
import azure.functions as func
from azure.core import exceptions as azure_exception
import json
import time

logger = logging.getLogger()
def kv_cred():
    logger.info("Getting default azure credentials")
    credential = DefaultAzureCredential()
    logger.debug(f"credential={credential}")
    KeyVaultName = "mar-keyvault"
    KVUri = f"https://{KeyVaultName}.vault.azure.net"
    logger.info(f"Creating KeyVault client for {KVUri}")
    client = SecretClient(vault_url=KVUri, credential=credential)
    logger.info(f"Client created with version {client.api_version}")
    return client


def main(req: func.HttpRequest) -> func.HttpResponse:
    logger.info('Python HTTP trigger function processed a request.--mar1')
    try:
        time_now = int(time.time())
        secretName = req.params.get('name')
        if not secretName:
            try:
                req_body = req.get_json()
                logger.info('get scret from req parameter')
            except ValueError:
                pass
            else:
                secretName = req_body.get('name')

        if secretName:
            try:
                client = kv_cred()
                logger.info(f"Getting secret for vaule {secretName}")
                retrieved_secret = client.get_secret(secretName)
                return func.HttpResponse(retrieved_secret.value)
            except azure_exception.ResourceNotFoundError as err:
                return func.HttpResponse(json.dumps({"type": "keyvault", "error": str(err)}), status_code=404, mimetype="application/json")
            except Exception as err:
                return func.HttpResponse(json.dumps({"type": "keyvault", "error": str(err)}), status_code=502, mimetype="application/json")
        else:
            try:
                logger.info(f"Default path: Querying CDN assets.")
                res = requests.get("https://static.licdn.com/sc/h/8nfuf4ujwbho8clwe5964984y", timeout=10)
                total_time = int(time.time()) - time_now
                return func.HttpResponse(
                    json.dumps({
                        "name": f"Azure Function Test", 
                        "epoch": int(time.time()),
                        "static_licdn": dict(res.headers),
                        "total_time_ms": total_time
                        }),
                    mimetype="application/json",
                    status_code=200
                )
            except Exception as err:
                return func.HttpResponse(json.dumps({"type": "outbound-licdn", "error": str(err)}), status_code=502, mimetype="application/json")
    except Exception as err:
        return func.HttpResponse(json.dumps({"type": "function-failure", "error": str(err)}), status_code=500, mimetype="application/json")
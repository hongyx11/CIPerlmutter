import os
import hmac
import hashlib
import json
import yaml
from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc7523 import PrivateKeyJWT
from litestar import Litestar, post, Request
from litestar.exceptions import HTTPException
import logging
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)


def read_file_content(file_path: str) -> str:
    """Read content from a file and return as a string."""
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            return content
    except Exception as e:
        logging.error(f"Error: {e}")
        return ""


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook signature."""
    mac = hmac.new(secret.encode(), msg=payload, digestmod=hashlib.sha256)
    expected_signature = f'sha256={mac.hexdigest()}'
    return hmac.compare_digest(expected_signature, signature)


def read_admission_conf(file_path: str) -> dict:
    """Read admission configuration."""
    try:
        with open(file_path, 'r') as file:
            yaml_content = yaml.safe_load(file)
            return yaml_content
    except Exception as e:
        logging.error(f"Error: {e}")
        return None


def check_admission(data: dict, admission_conf: dict):
    return_val = (False, False, False)

    if data['action'] != 'queued':
        logging.info("Not admitted, job not queued")
        return return_val
    if 'workflow_job' not in data:
        logging.info("Not admitted, not a workflow job event")
        return return_val

    if 'labels' not in data['workflow_job']:
        logging.info("Not admitted, no runner label specified")
        return return_val

    for i in admission_conf['repository']:
        if data['repository']['full_name'] != i['name']:
            continue
        elif data['workflow_job']['head_branch'] not in i['branch']:
            continue
        elif data['sender']['login'] not in i['user']:
            continue
        else:
            webhook_secret = read_file_content(i['webhook_secret'])
            return_val = (True, i['cluster'], webhook_secret)
            break
    return return_val


def run_job(data_dict: dict, clusters: dict) -> None:
    """Run the job."""
    # Implement the job logic here
    logging.info("Running the job...")
    logging.info(f"Repository: {data_dict['repository']['full_name']}")
    logging.info(f"Branch: {data_dict['workflow_job']['head_branch']}")
    logging.info(f"Sender: {data_dict['sender']['login']}")
    logging.info(clusters)
    if "perlmutter" in clusters and 'pm-login' in data_dict['workflow_job']['labels']:
        client_id = read_file_content(clusters['perlmutter']['client_id'])
        private_key = read_file_content(clusters['perlmutter']['private_key'])
        logging.info("Running on Perlmutter")
        logging.info(f"CLIENTID = {client_id}")
        logging.info(f"TOKEN_URL = {TOKEN_URL}")
        session = OAuth2Session( client_id, private_key, PrivateKeyJWT(TOKEN_URL), grant_type="client_credentials", token_endpoint=TOKEN_URL)
        session.fetch_token()
        cmd=f"start_runner.sh {data_dict['repository']['full_name']}"
        r = session.post("https://api.nersc.gov/api/v1.2/utilities/command/perlmutter", data = {"executable": cmd})
        logging.info(f"Superfacility API status: {r.json()}")
    logging.info("Job completed.")
    return None

@post("/webhook")
async def github_webhook(request: Request) -> dict:
    """Handle GitHub webhook."""
    try:
        payload = await request.body()
        logging.info("Received payload.")
        signature = request.headers.get("X-Hub-Signature-256")
        if not signature:
            raise HTTPException(status_code=400, detail="Missing signature header")
        data = json.loads(payload.decode('utf-8'))
        (admitted, clusters, webhook_secret) = check_admission(data, ADDMISSION_CONF)
        if not admitted:
            logging.info("job not admitted")
            return {"status": "job not admitted"}
        if not verify_signature(payload, signature, webhook_secret):
            raise HTTPException(status_code=400, detail="Invalid signature")
        if admitted:
            logging.info("Admission success")
            logging.info(f"data['action'] = {data['action']}")
            logging.info(f"data['repository']['full_name'] = {data['repository']['full_name']}")
            logging.info(f"data['workflow_job']['head_branch'] = {data['workflow_job']['head_branch']}")
            logging.info(f"data['sender']['login'] = {data['sender']['login']}")
            run_job(data, clusters)
            return {"status": "job admitted"}
        return {"status": "success, job not admitted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")


TOKEN_URL = os.environ.get("TOKEN_URL", "https://oidc.nersc.gov/c2id/token")
ADDMISSION_CONF_FILE = os.environ.get("ADDMISSION_CONF_FILE", "configs/admission.yaml")
ADDMISSION_CONF = read_admission_conf(ADDMISSION_CONF_FILE)
# More routes can be added here
app = Litestar(route_handlers=[github_webhook])


if __name__ == "__main__":
    app.run()

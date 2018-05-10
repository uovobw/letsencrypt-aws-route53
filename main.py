import sys
import logging

if sys.version_info.major != 3 or sys.version_info.minor != 6:
    # seriously, removing this won't help, it will break along the way
    # install python3.6, it's less painful
    logging.error("only python 3.6 is supported :(")
    sys.exit(1)

import os
from distutils.spawn import find_executable
import subprocess

import yaml
import boto3
import botocore

logger = logging.getLogger("le_aws")
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(stream=sys.stdout))

CONFIG_FILE="config.yml"
STATE_FILE="state.yml"
LE_PRODUCTION_SERVER="https://acme-v02.api.letsencrypt.org/directory"
LE_TEST_SERVER="https://acme-staging-v02.api.letsencrypt.org/directory"

def get_from_config(config, section, key):
    try:
        section_data = config[section]
        try:
            return section_data[key]
        except KeyError:
            logger.error("no key {} in section {}".format(key, section))
            sys.exit(1)
    except KeyError:
        logger.error("no section {} in configuration".format(section))
        sys.exit(1)

def call_aws(client, method, args=[], kwargs={}):
    try:
        a = getattr(client, method)
        return a(*args, **kwargs)
    except Exception as e:
        logger.error("error calling method {} on client {}: {}".format(
            method,
            client._service_model.service_name,
            e
        ))
        sys.exit(1)

# load configuration
if not os.path.exists(CONFIG_FILE):
    logger.error("no configuration file found in {}. aborting".format(CONFIG_FILE))
    sys.exit(1)

try:
    config = yaml.load(open(CONFIG_FILE).read())
except Exception as e:
    logger.error("error opening configuration file {}: {}. aborting".format(CONFIG_FILE, e))
    sys.exit(1)

# verify configuration to make sure binaries/dirs are there
le_work_directory = get_from_config(config, "letsencrypt", "work_directory")
certbot_binary = find_executable("certbot")
notification_email = get_from_config(config, "letsencrypt", "email")
test_mode = get_from_config(config, "letsencrypt", "test")
if not os.path.exists(le_work_directory):
    logger.error("cannot find work directory at {}, creating".format(le_work_directory))
    try:
        os.mkdir(le_work_directory)
    except Exception as e:
        logger.error("cannot create work directory at {}: {}. aborting".format(le_work_directory, e))
        sys.exit(1)

logs_directory = "{}/logs".format(le_work_directory)
config_directory = "{}/config".format(le_work_directory)
work_directory = "{}/work".format(le_work_directory)

logger.info("certbot running with log directory at {}, config directory at {} and work directory at {}".format(
    logs_directory,
    config_directory,
    work_directory
))

if certbot_binary is None:
    logger.error("cannot find \"certbot\" binary in path. aborting")
    sys.exit(1)

# create the boto clients checking for configuration params
aws_access_key = get_from_config(config, "aws", "access_key")
aws_access_secret = get_from_config(config, "aws", "access_secret")
aws_region = get_from_config(config, "aws", "region")
iam_client = boto3.client(
    "iam",
    region_name=aws_region,
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_access_secret
)
try:
    iam_client.list_server_certificates()
except botocore.exceptions.ClientError as e:
    logger.error("cannot initialize AWS IAM client: {}".format(e))
    sys.exit(1)

elb_client = boto3.client(
    "elb",
    region_name=aws_region,
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_access_secret
)
try:
    elb_client.describe_load_balancers()
except botocore.exceptions.ClientError as e:
    logger.error("cannot initialize AWS ELB client: {}".format(e))
    sys.exit(1)

# check that the configured load balancers are in fact existing
aws_load_balancers = call_aws(elb_client, "describe_load_balancers")
aws_load_balancers_names = [x.get("LoadBalancerName") for x in aws_load_balancers.get("LoadBalancerDescriptions")]
configured_load_balancers = get_from_config(config, "aws", "load_balancers")
for lb_name in configured_load_balancers:
    if lb_name not in aws_load_balancers_names:
        logger.error("load balancer {} not found in aws".format(lb_name))
        logger.error("found load balancers: {}".format(",".join(aws_load_balancers_names)))
        sys.exit(1)

# verify the state file
first_run = False
state = None
try:
    state = yaml.load(open(STATE_FILE).read())
except Exception as e:
    logger.warn("error opening state file {}: {}. considering this to be the first run".format(STATE_FILE, e))
    first_run = True
    state = {}


if first_run:
    logger.info("creating certificate for the first time")
    cmd = [certbot_binary,
           "certonly",
           "--dns-route53",
           "--logs-dir",
           logs_directory,
           "--config-dir",
           config_directory,
           "--work-dir",
           work_directory,
           "-m",
           notification_email,
           "--agree-tos",
           "--non-interactive",
           "--server"
          ]
    if test_mode:
        cmd.append(LE_TEST_SERVER)
    else:
        cmd.append(LE_PRODUCTION_SERVER)
    for domain in get_from_config(config, "letsencrypt", "domains"):
        cmd.append("-d")
        cmd.append(domain)
    logger.debug("running certbot as: {}".format(" ".join(cmd)))
    certbot = subprocess.Popen(
        cmd,
        stderr=subprocess.STDOUT,
        stdout=subprocess.PIPE,
        cwd=le_work_directory,
        encoding="utf-8",
        errors="ignore",
        env={
            "AWS_ACCESS_KEY_ID": aws_access_key,
            "AWS_SECRET_ACCESS_KEY": aws_access_secret
        }
    )
    certbot.wait()
    logger.info("certbot output:")
    for line in certbot.stdout:
        logger.info(line)
    if certbot.returncode != 0:
        logger.error("certbot returned {}. aborting.".format(certbot.returncode))
        sys.exit(1)
else:
    logger.info("renewing certificate")

# TODO: check that the created files are there
# TODO: get the expiration date from the cert itself
# TODO: create a new server certificate on IAM with the expiration date in the name
# TODO: iterate on each llistener of each load balancer to change the certificate to the new one
# TODO: state handling to allow for the "renew" command

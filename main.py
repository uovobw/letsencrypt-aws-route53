import sys
import logging

if sys.version_info.major != 3 or sys.version_info.minor < 6:
    # seriously, removing this won't help, it will break along the way
    # install python3.6, it's less painful
    logging.error("only python 3.6 is supported :(")
    sys.exit(1)

import os
import time
from distutils.spawn import find_executable
import subprocess
from dateutil import parser

import yaml
import boto3
import botocore
import OpenSSL

logger = logging.getLogger("le_aws")
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(stream=sys.stdout))

CONFIG_FILE="config.yml"
LE_PRODUCTION_SERVER="https://acme-v02.api.letsencrypt.org/directory"
LE_TEST_SERVER="https://acme-staging-v02.api.letsencrypt.org/directory"
LOAD_BALANCER_PORT=443
AWS_SLEEP_TIME=60

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

configured_domains = get_from_config(config, "letsencrypt", "domains")

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
for domain in configured_domains:
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

# check that the created files are there
created_files = [
    "cert.pem",
    "chain.pem",
    "fullchain.pem",
    "privkey.pem"
]
for created_file in created_files:
    found = False
    for domain in configured_domains:
        created_path = "{}/live/{}".format(config_directory, domain)
        if os.path.exists("{}/{}".format(created_path, created_file)):
            # for any configured domain we found a file matching that domain
            found = True
            break
    if not found:
        logger.error("file {} missing in path {}".format(created_file, created_path))
        sys.exit(1)

logger.info("all files found, checking expiration date")

certificate_data = open("{}/cert.pem".format(created_path)).read()
private_key_data = open("{}/privkey.pem".format(created_path)).read()
certificate_chain_data =  open("{}/chain.pem".format(created_path)).read()

loaded_certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_data)
expiration_date = parser.parse(loaded_certificate.get_notAfter())

logger.info("current expiration date: {}".format(expiration_date))

# create an IAM server certificate

iam_certificate_name = "le_certificate_exp_{}".format(expiration_date.strftime("%Y_%m_%d"))
try:
    iam_certificate_data = iam_client.upload_server_certificate(
        ServerCertificateName=iam_certificate_name,
        CertificateBody=certificate_data,
        PrivateKey=private_key_data,
        CertificateChain=certificate_chain_data
    )
except Exception as e:
    logger.error("error creating new certificate {}: {}".format(iam_certificate_name, e))
    sys.exit(1)

# we can call the [] directly, if this fails amazon has changed the api and boto and 2/3 of the internet are
# broken
iam_certificate_id = iam_certificate_data["ServerCertificateMetadata"]["Arn"]
logger.info("created server certificate with name {} and ARN {}".format(iam_certificate_name, iam_certificate_id))

# we need to sleep about 1 minutes, or the elb operation will fail due to replication times
logger.info("sleeping {} seconds to allow the cert to propagate".format(AWS_SLEEP_TIME))
time.sleep(AWS_SLEEP_TIME)
logger.info("sleep done")

# iterate on each llistener of each load balancer to change the certificate to the new one
for load_balancer_name in configured_load_balancers:
    logger.info("updating certificate for load balancer: {}".format(load_balancer_name))
    try:
        response = elb_client.set_load_balancer_listener_ssl_certificate(
            LoadBalancerName=load_balancer_name,
            LoadBalancerPort=LOAD_BALANCER_PORT,
            SSLCertificateId=iam_certificate_id
        )
    except Exception as e:
        logger.error("error setting new certificate for load balancer {}: {}".format(load_balancer_name, e))
        sys.exit(1)

logger.info("done")

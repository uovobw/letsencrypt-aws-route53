# LetsEncrypt + AWS Load Balancers

This script is used to generate a new LetsEncrypt wildcard certificate - as time
of writing valid for 90 days - and then use the AWS api to push onto one or 
more load balancer listeners.

## Dependencies

The software uses a number of external libraries, they can all be installed by
running the command

```
pip install -r requirements.txt
```

from the main repository root. A virtualenv is recommended but not strictly
necessary.

## AWS Configuration

In order to be able to answer the route53 LetsEncrypt challenge, create
the server certificate on IAM and change the ELB listeners to use it, a specially
configured AWS user must be configured. A policy file can be found in the `policy`
directory. The user access key and secrets are those that must be provided in the configuration
file before running the script.

## Usage

Customize the `config.yml.example` by renaming it `config.yml` and replacing the relevant
configuration inside it, then run the script by invoking

```
python main.py
```

The script will output the various steps of the process and print the certbot invocation
on stdout.

## Disclaimer

This software has been written to solve a limited and specific problem that is relevant to my problem space, it
might or might not be suited for different applications or environments, it has been tested only by being used
seldomly in the last couple of years to renew a number of certificates for AWS-hosted domains. 
*USE AT YOUR OWN RISK* and do not come complaining to me if the software leaks your credentials, deletes all 
your AWS resources due to an undiscovered bug, kills your cat or any other uninteded consequence.

## Contact

Andrea Lusuardi - me@uovobw.net

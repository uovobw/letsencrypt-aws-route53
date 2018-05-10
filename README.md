# LetsEncrypt + AWS Load Balancers

This software is a collection of scripts used to generate a new LetsEncrypt
wildcard certificate - as time of writing valid for 90 days - and then use
the AWS api to push onto one or more load balancer listeners.

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
directory.

## Contact

Andrea Lusuardi - uovobw@gmail.com

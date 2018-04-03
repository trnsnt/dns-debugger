# DNS DEBUGGER
dns-debugger is here to help you to find why a DNS zone is not working.

**/!\ For now it's just a pre-alpha POC ;) /!\\**

A lot of stuff is not yet implemented, **it's not tested**, and it **can crash at anytime** !

## What it does ?
Goal is to help you to find why a DNS zone is not working. To do this, it will
* Query your zone with your default resolver
* Query your zone with famous resolvers (8.8.8.8, ...)
* Recursively query your zone
* Check DNSSEC chain of trust

## How to use it

### Installation 
#### Prerequisites
 * Python 3.6
 * pipenv https://docs.pipenv.org/
```
$ pipenv shell
```

### Usage
```
usage: __main__.py [-h] [-d QNAME] [-x UI] [--all] [--failures]

optional arguments:
  -h, --help            show this help message and exit
  -d QNAME, --domain    QNAME
                        FQDN of the DNS zone you want to test
  -x UI, --ui UI        Wanted display console|server
  --all                 Display all testcases
  --failures            Display only testcases in failure
```

### Run it with console
```
$ python -m dns_debugger -d trnsnt.ovh --failures
{
  "success": 0,
  "failures": 1,
  "testcases": {
    "failures": [
      {
        "description": "Checking DNSSEC recursively for trnsnt.ovh.",
        "result": "Zone trnsnt.ovh. is not signed, there is no DNSKEY, but we have a parent DS record. Please remove it",
        "success": false
      }
    ]
  }
}

$ python -m dns_debugger -d dnstests.fr
{
  "success": 26,
  "failures": 0,
  "testcases": {
    "failures": [],
    "success": [
      {
        "description": "Get SOA records for dnstests.fr. from default resolver",
        "result": "[RRSET] [[SOA] dan.ns.cloudflare.com. dns.cloudflare.com. 2027406459 10000 2400 604800 3600]",
        "success": true
      }
    ]
  }
}

```

### Run it with Flask
```
$ python -m dns_debugger -x server
$ curl http://127.0.0.1:5000/dnstests.fr
{
  "success": 26,
  "failures": 0,
  "testcases": {
    "failures": [],
    "success": [
      {
        "description": "Get SOA records for dnstests.fr. from default resolver",
        "result": "[RRSET] [[SOA] dan.ns.cloudflare.com. dns.cloudflare.com. 2027406459 10000 2400 604800 3600]",
        "success": true
      }
    ]
  }
}
```
#### With docker
```
$ docker build -t dns-debugger:latest .
$ docker run -p 5000:5000 dns-debugger:latest
```

## What to do next ?
 * Implement all DNSSEC algorithms
 * Improve DNSSEC validation: NSEC, NSEC3, ...
 * Make unittests
 * Add results analyzer to have in output where the problem is
 * Get rid of _rdata in Record
 * Support of Docker for server mode
 * ...
  
## Thanks
Some parts of the code are inspired 
 * dnsviz - https://github.com/dnsviz/dnsviz
 * dnspython - https://github.com/rthalley/dnspython
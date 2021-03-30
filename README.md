# pysshconfig

[![Python package](https://github.com/zfrank/pysshconfig/actions/workflows/python-package.yml/badge.svg)](https://github.com/zfrank/pysshconfig/actions/workflows/python-package.yml)
[![codecov](https://codecov.io/gh/zfrank/pysshconfig/branch/master/graph/badge.svg?token=PYRHK0K3ZJ)](https://codecov.io/gh/zfrank/pysshconfig)

Extremely simple, pure-python library to read ssh_config files.
Useful to see what keywords/options are applied to a certain host, just like the
official ssh client would.

Requires Python >=3.5

## Example usage
Let's say your `~/.ssh/config` file looks like this:

```
Host special.example.net
    User root
    Port 2222

Host *.example.com !insecure.example.com
    ForwardAgent yes
    User johndoe
    PreferredAuthentications publickey

Host *
    ForwardAgent no
    HashKnownHosts no
```

Then you can parse it like this:

```
import os.path
import pysshconfig as psc
with open(os.path.expanduser('~/.ssh/config')) as f:
    ssh_config = psc.load(f)
```

Now check what keywords are applied to a certain host like this:

```
>>> ssh_config.get_config_for_host('somehost.example.com')
{'ForwardAgent': 'yes', 'User': 'johndoe', 'PreferredAuthentications': 'publickey', 'HashKnownHosts': 'no'}

>>> ssh_config.get_config_for_host('insecure.example.com')
{'ForwardAgent': 'no', 'HashKnownHosts': 'no'}

>>> ssh_config.get_config_for_host('special.example.net')
{'User': 'root', 'Port': '2222', 'Forwardagent': 'yes', 'Preferredauthentications': 'publickey', 'HashKnownHosts': 'no'}
```

Adding a new Host block is as easy as modifying a list:
```
>>> myhosts = ['newhost.example.com', '*.www.example.com', '!test.www.example.com']
>>> myoptions = {'user': 'bob', 'port': '8080'}
>>> ssh_config.insert(0, psc.HostBlock(psc.HostList(myhosts), psc.KeywordSet(myoptions)))

>>> psc.dumps(ssh_config)
Host newhost.example.com *.www.example.com !test.www.example.com
    User bob
    Port 8080

Host special.example.net
    User root
    Port 2222

Host *.example.com !insecure.example.com special.example.net
    ForwardAgent yes
    User johndoe
    PreferredAuthentications publickey

Host *
    ForwardAgent no
    HashKnownHosts no
```

You can modify existing keywords as if they were dictionaries:
```
>>> hostblocks = ssh_config.get_matching_hosts('host.www.example.com')
>>> for _, kw in hostblocks:
...    kw['user'] = "alice"
...
>>> psc.dumps(ssh_config)
Host newhost.example.com *.www.example.com !test.www.example.com
    User alice
    Port 8080

Host special.example.net
    User root
    Port 2222

Host *.example.com !insecure.example.com special.example.net
    ForwardAgent yes
    User alice
    PreferredAuthentications publickey

Host *
    ForwardAgent no
    HashKnownHosts no
    User alice
```

## Limitations
Formatting from the original file will not be preserved. To be more specific:
  * The keywords will change to match the correct case ('hashknownhosts' -> 'HashKnownHosts')
  * Comments and empty lines will be removed

It will validate that the keywords are correct, but it does not perform any validation on their values.

It does not support the `Match` keyword yet.

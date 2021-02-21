# pysshconfig
Extremely simple, pure-python library to read ssh_config files.
Useful to see what keywords/options are applied to a certain host, just like the
official ssh client would.

## Example usage
Let's say your `~/.ssh/config` file looks like this:

```
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

Then you can parse it like this:

```
import os.path
import pysshconfig
with open(os.path.expanduser('~/.ssh/config')) as f:
    ssh_config = pysshconfig.load(f)
```

Now check what keywords are applied to a certain host like this:

```
>>> ssh_config.get('somehost.example.com')
{'forwardagent': 'yes', 'user': 'johndoe', 'preferredauthentications': 'publickey', 'hashknownhosts': 'no'}

>>> ssh_config.get('insecure.example.com')
{'forwardagent': 'no', 'hashknownhosts': 'no'}

>>> ssh_config.get('special.example.net')
{'user': 'root', 'port': '2222', 'forwardagent': 'yes', 'preferredauthentications': 'publickey', 'hashknownhosts': 'no'}
```

## Limitations
It does not support *writing*. This library does not provide any way to perform
changes on files. Any changes you make to the data structures will not be
applied to your files on disk.

It will validate that the keywords are correct, but it does not perform any
validation on values.

It does not support the `Match` keyword yet.

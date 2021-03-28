#!/usr/bin/env python3
#
#    Copyright (c) 2021 Francesc Zacarias
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published
#    by the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.


from typing import Dict, Generator, List, NamedTuple, TextIO, Tuple
try:
    from typing import OrderedDict
except ImportError:  # py3.6
    from collections import OrderedDict

import fnmatch
import re


VALID_KEYWORDS = [
    "AddKeysToAgent",
    "AddressFamily",
    "BatchMode",
    "BindAddress",
    "BindInterface",
    "CanonicalDomains",
    "CanonicalizeFallbackLocal",
    "CanonicalizeHostname",
    "CanonicalizeMaxDots",
    "CanonicalizePermittedCNAMEs",
    "CASignatureAlgorithms",
    "CertificateFile",
    "ChallengeResponseAuthentication",
    "CheckHostIP",
    "Ciphers",
    "ClearAllForwardings",
    "Compression",
    "ConnectionAttempts",
    "ConnectTimeout",
    "ControlMaster",
    "ControlPath",
    "ControlPersist",
    "DynamicForward",
    "EnableSSHKeysign",
    "EscapeChar",
    "ExitOnForwardFailure",
    "FingerprintHash",
    "ForwardAgent",
    "ForwardX11",
    "ForwardX11Timeout",
    "ForwardX11Trusted",
    "GatewayPorts",
    "GlobalKnownHostsFile",
    "GSSAPIAuthentication",
    "GSSAPIClientIdentity",
    "GSSAPIDelegateCredentials",
    "GSSAPIKeyExchange",
    "GSSAPIRenewalForcesRekey",
    "GSSAPIServerIdentity",
    "GSSAPITrustDns",
    "GSSAPIKexAlgorithms",
    "HashKnownHosts",
    "HostbasedAuthentication",
    "HostbasedKeyTypes",
    "HostKeyAlgorithms",
    "HostKeyAlias",
    "Hostname",
    "IdentitiesOnly",
    "IdentityAgent",
    "IdentityFile",
    "IgnoreUnknown",
    "Include",
    "IPQoS",
    "KbdInteractiveAuthentication",
    "KbdInteractiveDevices",
    "KexAlgorithms",
    "LocalCommand",
    "LocalForward",
    "LogLevel",
    "MACs",
    "NoHostAuthenticationForLocalhost",
    "NumberOfPasswordPrompts",
    "PasswordAuthentication",
    "PermitLocalCommand",
    "PKCS11Provider",
    "Port",
    "PreferredAuthentications",
    "ProxyCommand",
    "ProxyJump",
    "ProxyUseFdpass",
    "PubkeyAcceptedKeyTypes",
    "PubkeyAuthentication",
    "RekeyLimit",
    "RemoteCommand",
    "RemoteForward",
    "RequestTTY",
    "RevokedHostKeys",
    "SecurityKeyProvider",
    "SendEnv",
    "ServerAliveCountMax",
    "ServerAliveInterval",
    "SetEnv",
    "StreamLocalBindMask",
    "StreamLocalBindUnlink",
    "StrictHostKeyChecking",
    "SyslogFacility",
    "TCPKeepAlive",
    "Tunnel",
    "TunnelDevice",
    "UpdateHostKeys",
    "User",
    "UserKnownHostsFile",
    "VerifyHostKeyDNS",
    "VisualHostKey",
    "XAuthLocation",
]
KEYWORD_CASE = {k.lower(): k for k in VALID_KEYWORDS}


class InvalidKeyword(Exception):
    pass


def norm_key(k: str) -> str:
    try:
        return KEYWORD_CASE[k.lower()]
    except KeyError:
        raise InvalidKeyword("Keyword {} is not valid".format(k))


class ParserError(Exception):
    pass


class HostList(List[str]):
    def match(self, hostname: str) -> bool:
        '''
        Return True if any entry in the HostList matches hostname. Entries can be made negative by
        preceeding them with '!'.
        '''
        if not hostname:
            return False
        match_positive = False
        for h in self:
            if h.startswith('!'):
                h = h[1:]
                if fnmatch.fnmatch(hostname, h):
                    return False
            else:
                if fnmatch.fnmatch(hostname, h):
                    match_positive = True
        if match_positive:
            return True
        return False


class KeywordSet(OrderedDict):
    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            raise TypeError
        return super().__contains__(norm_key(key))

    def __getitem__(self, key: str) -> str:
        return super().__getitem__(norm_key(key))

    def __setitem__(self, key: str, value: str) -> None:
        super().__setitem__(norm_key(key), value)


HostBlock = NamedTuple('HostBlock', [('hosts', HostList), ('keywords', KeywordSet)])


class SshConfig(List[HostBlock]):
    def get_matching_hosts(self, hostname: str) -> List[HostBlock]:
        '''
        Return a list of all HostBlock objects that match hostname.
        '''
        return [hb for hb in self if hb.hosts.match(hostname)]

    def get_config_for_host(self, hostname: str) -> Dict[str, str]:
        '''
        Return all the configuration keywords that apply to hostname.
        '''
        result = KeywordSet()
        for hostlist, keywords in self:
            if not hostlist.match(hostname):
                continue
            for k, v in keywords.items():
                if k not in result:
                    result[k] = v
        return result


class SshParser:
    def __init__(self) -> None:
        self.ssh_config = SshConfig()
        self.current_host = HostList(['*'])
        self.current_values = KeywordSet()
        self.line_num = 0
        self.first = True

    def parse(self, data: str) -> SshConfig:
        for line in data.splitlines():
            self.line_num += 1
            if re.match(r'^\s*$', line) or re.match(r'^\s*#', line):
                # ignore comments and empty lines
                continue
            elif re.match(r'\s*host\s+', line, flags=re.IGNORECASE):
                self._parse_host(line)
            elif re.match(r'\s*match\s+', line, flags=re.IGNORECASE):
                raise NotImplementedError("Match keyword is not supported by pysshconfig")
            else:
                # parse keyword
                self._parse_keyword(line)
        self._close_current()
        return self.ssh_config

    def _close_current(self) -> None:
        '''Finish current Host declaration'''
        if self.first:
            self.first = False
            if not self.current_values:
                # Skip the first HostBlock if it's empty (dummy)
                return
        self.ssh_config.append(HostBlock(self.current_host, self.current_values))
        self.current_values = KeywordSet()

    def _parse_host(self, line: str) -> None:
        self._close_current()
        hosts = self.__class__._parse_host_line(line)
        hl = HostList(hosts)
        self.current_host = hl

    @staticmethod
    def _parse_host_line(line: str) -> List[str]:
        '''Extract a list of hosts from a Host keyword'''
        host_line = re.sub(r'\s*host\s+', '', line, count=1, flags=re.IGNORECASE)
        return host_line.split()

    def _parse_keyword(self, line: str) -> None:
        '''Parse any keyword except Host or Match'''
        line = line.lstrip()
        try:
            keyword, value = self.__class__._parse_keyword_line(line)
        except ValueError:
            # not enough values to unpack
            raise ParserError("Invalid syntax at line {}: {}".format(self.line_num, line))
        if keyword.lower() not in KEYWORD_CASE:
            raise ParserError("Invalid keyword at line {}: {}".format(self.line_num, keyword))
        if keyword not in self.current_values:
            self.current_values[keyword] = value

    @staticmethod
    def _parse_keyword_line(line: str) -> Tuple[str, str]:
        k, v = line.split(maxsplit=1)
        return k, v


def load(data: TextIO) -> SshConfig:
    return loads(data.read())


def loads(data: str) -> SshConfig:
    return SshParser().parse(data)


def _str_generator(ssh_config: SshConfig, indent: str = '    ', sep_lines: int = 1) -> Generator[str, None, None]:
    last = len(ssh_config) - 1
    for i, hb in enumerate(ssh_config):
        if not isinstance(hb, HostBlock):
            raise TypeError
        hl, kw = hb
        hosts_str = ' '.join(hl)
        yield "Host {}\n".format(hosts_str)
        for k, v in kw.items():
            yield "{}{} {}\n".format(indent, k, v)
        if i == last:
            break
        for num in range(sep_lines):
            yield "\n"


def dump(ssh_config: SshConfig, fp: TextIO, indent: str = '    ', sep_lines: int = 1) -> None:
    for line in _str_generator(ssh_config, indent, sep_lines):
        fp.write(line)


def dumps(ssh_config: SshConfig, indent: str = '    ', sep_lines: int = 1) -> str:
    return "".join(_str_generator(ssh_config, indent, sep_lines))

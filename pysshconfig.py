#!/usr/bin/env python3

from __future__ import annotations
from typing import Dict, List, Optional, OrderedDict, TextIO, Tuple
import collections.abc
import fnmatch
import re
import sys


HostList = Optional[Tuple[str, ...]]
VALID_KEYWORDS = [
    "Host",
    "Match",
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


def load(data: TextIO) -> SshConfig:
    return loads(data.read())


def loads(data: str) -> SshConfig:
    return SshParser().parse(data)


class ParserError(Exception):
    pass


class SshParser:
    def __init__(self) -> None:
        self.ssh_config = SshConfig()
        self.current_host: HostList = None
        self.current_values = KeywordSet()

    def parse(self, data: str) -> SshConfig:
        for line in data.splitlines():
            # remove comments
            line = re.sub('#.*', '', line, count=1)
            if re.match(r'^\s*$', line):
                # ignore empty lines
                continue
            elif re.match(r'\s*host\s+', line, flags=re.IGNORECASE):
                self._parse_host(line)
            elif re.match(r'\s*match\s+', line, flags=re.IGNORECASE):
                raise NotImplemented
            else:
                # parse keyword
                if not self.current_host:
                    print(f"Keyword argument outside of Host or Match: {line}", file=sys.stderr)
                    continue
                self._parse_keyword(line)
        self._close_current()
        return self.ssh_config

    def _close_current(self) -> None:
        '''Finish current Host declaration'''
        if self.current_host:
            self.ssh_config.add(self.current_host, self.current_values)
        self.current_host = None
        self.current_values = KeywordSet()

    def _parse_host(self, line: str) -> None:
        '''Parse Host keyword'''
        self._close_current()
        hosts_line = re.sub('\s*host\s+', '', line, count=1, flags=re.IGNORECASE)
        self.current_host = tuple(hosts_line.split()) or None
        if not self.current_host:
            raise ParserError("Empty Host keyword")

    def _parse_keyword(self, line: str) -> None:
        '''Parse any keyword except Host or Match'''
        line = line.lstrip()
        keyword, value = line.split(maxsplit=1)
        if keyword.lower() not in KEYWORD_CASE:
            raise ParserError(f"Invalid keyword: {keyword}")
        if keyword in self.current_values:
            return
        self.current_values[keyword] = value


class KeywordSet(Dict[str, str]):
    '''
    A simple wrapper around a regular dictionary that makes all keys lowercase.
    All ssh_config keywords are case-insensitive and this makes testing for
    a match easier.
    '''

    def __init__(self, first=None, **kwargs) -> None:
        if first:
            if issubclass(first.__class__, collections.abc.Mapping):
                for k, v in first.items():
                    self[k] = v
            elif issubclass(first.__class__, collections.abc.Iterable):
                for k, v in first:
                    self[k] = v
        for k, v in kwargs.items():
            self[k] = v

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            raise TypeError('key must be str')
        return super().__contains__(key.lower())

    def __getitem__(self, key: str) -> str:
        return super().__getitem__(key.lower())

    def __setitem__(self, key: str, value: str) -> None:
        return super().__setitem__(key.lower(), value)

    def update(self, *kws, **kwargs) -> None:
        '''
        Add all values in kw2 to kw1 if they are not present.
        Like a regulard dict1.update(dict2) but don't override existing values.
        '''
        for kw in kws:
            for k, v in kw.items():
                if k in self:
                    continue
                self[k] = v
        for k, v in kwargs.items():
            if k in self:
                continue
            self[k] = v


class SshConfig:
    def __init__(self) -> None:
        self.ssh_config: OrderedDict[HostList, KeywordSet] = OrderedDict()

    def __repr__(self) -> str:
        return repr(self.ssh_config)

    def add(self, host: HostList, values: KeywordSet) -> None:
        '''
        Add a new Host and its declarations to the config.
        If the Host entry already exists, then merge the values (first one wins).
        '''
        if host in self.ssh_config:
            self.ssh_config[host].update(values)
        else:
            self.ssh_config[host] = values

    @staticmethod
    def match_host(hostname: str, hostlist: HostList) -> bool:
        if not hostname:
            raise ValueError("hostname cannot be empty")
        if not hostlist:
            return False
        match_positive = False
        match_negative = False
        for h in hostlist:
            if h.startswith('!'):
                h = h[1:]
                if fnmatch.fnmatch(hostname, h):
                    match_negative = True
            else:
                if fnmatch.fnmatch(hostname, h):
                    match_positive = True
        if match_negative:
            return False
        if match_positive:
            return True
        return False

    def get(self, hostname: str) -> KeywordSet:
        """ Return all the configuration keywords that apply to hostname"""
        result = KeywordSet()
        for hostlist, keywords in self.ssh_config.items():
            if SshConfig.match_host(hostname, hostlist):
                result.update(keywords)
        return result

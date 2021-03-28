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

from pysshconfig import HostBlock, HostList, InvalidKeyword, KeywordSet, ParserError, dump, dumps, load, loads
from io import StringIO
import textwrap
import unittest


class TestMatchHost(unittest.TestCase):
    def test_positive_match(self):
        self.assertTrue(HostList(['onehost', 'myhost']).match('myhost'))

    def test_positive_match_pattern(self):
        self.assertTrue(HostList(['onehost', '*host']).match('myhost'))

    def test_negative_match_over_positive_match(self):
        self.assertFalse(HostList(['*host', '!*host']).match('myhost'))

    def test_no_match(self):
        self.assertFalse(HostList(['onehost', 'somehost']).match('myhost'))

    def test_match_all(self):
        self.assertTrue(HostList(['*']).match('myhost'))

    def test_empty_list(self):
        self.assertFalse(HostList([]).match('myhost'))

    def test_empty_host(self):
        self.assertFalse(HostList(['*']).match(''))


class TestKeywordSet(unittest.TestCase):
    def test_set_bad_key(self):
        kw = KeywordSet()
        with self.assertRaises(InvalidKeyword):
            kw['invalidkey'] = 'data'

    def test_case_insensitve(self):
        value = 'alice'
        kw = KeywordSet({'user': value})
        for key in ['User', 'USER', 'user']:
            self.assertIn(key, kw)
            self.assertEqual(value, kw[key])

    def test_cannot_have_host_and_match_in_keywordset(self):
        kw = KeywordSet()
        with self.assertRaises(InvalidKeyword):
            kw['Host'] = 'myhost.org'
        with self.assertRaises(InvalidKeyword):
            kw['Match'] = 'host myhost.org'


class TestSshParser(unittest.TestCase):
    def test_parse_simple(self):
        config = textwrap.dedent('''\
        Host myhost.com
            PreferredAuthentications publickey
            User myuser
            ForwardAgent no
        ''')
        ssh_config = loads(config)
        kw = ssh_config.get_config_for_host('myhost.com')

        self.assertEqual('publickey', kw['PreferredAuthentications'])
        self.assertEqual('myuser', kw['User'])
        self.assertEqual('no', kw['ForwardAgent'])

    def test_load_equals_loads(self):
        config = textwrap.dedent('''\
        Host myhost.com
            PreferredAuthentications publickey
            User myuser
            ForwardAgent no
        ''')
        ssh_config_load = loads(config)
        ssh_config_loads = load(StringIO(config))

        self.assertEqual(ssh_config_load, ssh_config_loads)

    def test_parse_duplicate_keywords(self):
        config = textwrap.dedent('''\
        Host myhost.com
            PreferredAuthentications publickey
            User myuser
            ForwardAgent no
            User nobody
        ''')
        ssh_config = loads(config)
        kw = ssh_config.get_config_for_host('myhost.com')
        self.assertEqual('myuser', kw['User'])

    def test_parse_multiple_hostblocks(self):
        config = textwrap.dedent('''\
        Host myhost.com
            PreferredAuthentications publickey
            User myuser
            ForwardAgent no

        Host *.com
            User nobody
            HashKnownHosts yes
        ''')
        ssh_config = loads(config)
        kw = ssh_config.get_config_for_host('myhost.com')
        self.assertEqual('publickey', kw['PreferredAuthentications'])
        self.assertEqual('myuser', kw['User'])
        self.assertEqual('no', kw['ForwardAgent'])
        self.assertEqual('yes', kw['HashKnownHosts'])
        self.assertEqual(2, len(ssh_config.get_matching_hosts('myhost.com')))

    def test_top_keywords_without_hostblock(self):
        config = textwrap.dedent('''\
        ForwardX11 no

        Host myhost.com
            PreferredAuthentications publickey
            User myuser
            ForwardAgent yes
            ForwardX11 yes

        Host *.com
            User nobody
            HashKnownHosts yes
        ''')
        ssh_config = loads(config)
        kw = ssh_config.get_config_for_host('myhost.com')
        self.assertEqual('no', kw['ForwardX11'])
        self.assertEqual(3, len(ssh_config.get_matching_hosts('myhost.com')))

    def test_ignore_comments_and_spaces(self):
        config = textwrap.dedent('''\
        # Host myhost.net
        # user auser

        Host myhost.com myhost.org

          # some text
        preferredauthentications password
        user myuser

        # forwardagent no

        host *
        forwardagent yes

        ''')
        ssh_config = loads(config)

        self.assertEqual({'ForwardAgent': 'yes'}, ssh_config.get_config_for_host('myhost.net'))
        self.assertEqual('yes', ssh_config.get_config_for_host('myhost.com')['ForwardAgent'])

    def test_load_and_dump(self):
        config = textwrap.dedent('''\
        Host myhost.com
            PreferredAuthentications publickey
            User myuser
            ForwardAgent no

        Host myhost.net myhost.org
            User bob
            Port 23
        ''')
        ssh_config = loads(config)
        self.assertEqual(config, dumps(ssh_config))

    def test_dump_equals_dumps(self):
        config = textwrap.dedent('''\
        Host myhost.com
            PreferredAuthentications publickey
            User myuser
            ForwardAgent no

        Host myhost.net myhost.org
            User bob
            Port 23
        ''')
        ssh_config = loads(config)
        fd = StringIO()
        dump(ssh_config, fd)
        self.assertEqual(dumps(ssh_config), fd.getvalue())

    def test_append_hostlist(self):
        expected = textwrap.dedent('''\
        Host myhost.com
            PreferredAuthentications publickey
            User myuser
            ForwardAgent no

        Host myhost.net myhost.org
            User bob
            Port 23
        ''')

        config = textwrap.dedent('''\
        Host myhost.com
            PreferredAuthentications publickey
            User myuser
            ForwardAgent no''')

        ssh_config = loads(config)
        ssh_config.append(HostBlock(
            HostList(["myhost.net", "myhost.org"]),
            KeywordSet([
                ("User", "bob"),
                ("Port", "23"),
            ]),
        ))
        self.assertEqual(expected, dumps(ssh_config))


class TestSshParserErrors(unittest.TestCase):
    def test_parse_bad_keyword(self):
        config = textwrap.dedent('''\
        Host myhost.com
            badkeyword no
        ''')
        with self.assertRaises(ParserError) as cm:
            _ = loads(config)

        self.assertEqual("Invalid keyword at line 2: badkeyword", str(cm.exception))

    def test_parse_bad_syntax(self):
        config = textwrap.dedent('''\
        Host myhost.com
            ProxyJump
        ''')
        with self.assertRaises(ParserError) as cm:
            _ = loads(config)

        self.assertEqual("Invalid syntax at line 2: ProxyJump", str(cm.exception))


class TestSshParserFormatting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.Config = textwrap.dedent('''\
        ConnectTimeout 30
        Host myhost.com !insecure.com
        PreferredAuthentications publickey
        User alice
         ForwardAgent no



        Host myhost.net myhost.org
            User bob
            Port 23
        Host *
        User nouser
                ForwardX11 no

        ''')

    def test_default_format(self):
        expected = textwrap.dedent('''\
        Host *
            ConnectTimeout 30

        Host myhost.com !insecure.com
            PreferredAuthentications publickey
            User alice
            ForwardAgent no

        Host myhost.net myhost.org
            User bob
            Port 23

        Host *
            User nouser
            ForwardX11 no
        ''')
        config = self.__class__.Config
        ssh_config = loads(config)
        self.assertEqual(expected, dumps(ssh_config))

    def test_no_sep_lines(self):
        expected = textwrap.dedent('''\
        Host *
            ConnectTimeout 30
        Host myhost.com !insecure.com
            PreferredAuthentications publickey
            User alice
            ForwardAgent no
        Host myhost.net myhost.org
            User bob
            Port 23
        Host *
            User nouser
            ForwardX11 no
        ''')
        config = self.__class__.Config
        ssh_config = loads(config)
        self.assertEqual(expected, dumps(ssh_config, sep_lines=0))

    def test_indent_tabs(self):
        expected = textwrap.dedent('''\
        Host *
        \tConnectTimeout 30

        Host myhost.com !insecure.com
        \tPreferredAuthentications publickey
        \tUser alice
        \tForwardAgent no

        Host myhost.net myhost.org
        \tUser bob
        \tPort 23

        Host *
        \tUser nouser
        \tForwardX11 no
        ''')
        config = self.__class__.Config
        ssh_config = loads(config)
        self.assertEqual(expected, dumps(ssh_config, indent='\t'))


if __name__ == '__main__':
    unittest.main(verbosity=2)

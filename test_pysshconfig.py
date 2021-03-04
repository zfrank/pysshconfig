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

import pysshconfig
import textwrap
import unittest


class TestMatchHost(unittest.TestCase):
    def test_positive_match(self):
        self.assertTrue(pysshconfig.SshConfig.match_host('myhost', ('onehost', 'myhost')))

    def test_positive_match_pattern(self):
        self.assertTrue(pysshconfig.SshConfig.match_host('myhost', ('onehost' '*host')))

    def test_negative_match_over_positive_match(self):
        self.assertFalse(pysshconfig.SshConfig.match_host('myhost', ('*host', '!*host')))

    def test_no_match(self):
        self.assertFalse(pysshconfig.SshConfig.match_host('myhost', ('onehost', 'somehost')))

    def test_match_all(self):
        self.assertTrue(pysshconfig.SshConfig.match_host('myhost', ('*')))

    def test_empty_list(self):
        self.assertFalse(pysshconfig.SshConfig.match_host('myhost', ()))

    def test_empty_host(self):
        with self.assertRaises(ValueError):
            self.assertFalse(pysshconfig.SshConfig.match_host('', ('*')))


class TestKeywordSet(unittest.TestCase):
    def setUp(self):
        self.init_l = [
            ('one', 1),
            ('two', 2),
            ('three', 3),
        ]
        self.init_d = dict(self.init_l)

    def test_empty(self):
        kw = pysshconfig.KeywordSet()
        self.assertEqual({}, kw)

    def test_init_from_iterable(self):
        kw = pysshconfig.KeywordSet(self.init_l)
        self.assertEqual(self.init_d, kw)

    def test_init_from_mapping(self):
        kw = pysshconfig.KeywordSet(self.init_d)
        self.assertEqual(self.init_d, kw)

    def test_init_from_keyword_args(self):
        dk = dict(**self.init_d)
        kw = pysshconfig.KeywordSet(**self.init_d)
        self.assertEqual(dk, kw)

    def test_contains_set_and_get_item(self):
        kw = pysshconfig.KeywordSet([('User', 'a')])
        self.assertIn('User', kw)
        self.assertIn('user', kw)
        self.assertIn('USER', kw)
        self.assertEqual('a', kw['User'])
        self.assertEqual('a', kw['user'])
        self.assertEqual('a', kw['USER'])

    def test_update(self):
        kw1 = pysshconfig.KeywordSet({
            'User': 'a',
            'HashKnownHosts': 'yes',
        })
        kw2 = pysshconfig.KeywordSet({
            'User': 'b',
            'ForwardAgent': 'yes',
        })
        kw1.update(kw2)
        self.assertEqual('a', kw1['User'])
        self.assertEqual('yes', kw1['HashKnownHosts'])
        self.assertEqual('yes', kw1['ForwardAgent'])


class TestSshParser(unittest.TestCase):
    def test_parse_simple(self):
        config = textwrap.dedent('''\
        Host myhost.com
            PreferredAuthentications publickey
            User myuser
            ForwardAgent no''')
        ssh_config = pysshconfig.loads(config)
        kw = ssh_config.get('myhost.com')
        self.assertEqual('publickey', kw['PreferredAuthentications'])
        self.assertEqual('myuser', kw['User'])
        self.assertEqual('no', kw['ForwardAgent'])

    def test_parse_multiple_hosts(self):
        config = textwrap.dedent('''\
        Host myhost.com
            PreferredAuthentications publickey
            User myuser
            ForwardAgent no

        Host *.com
            HashKnownHosts yes''')
        ssh_config = pysshconfig.loads(config)
        kw = ssh_config.get('myhost.com')
        self.assertEqual('publickey', kw['PreferredAuthentications'])
        self.assertEqual('myuser', kw['User'])
        self.assertEqual('no', kw['ForwardAgent'])
        self.assertEqual('yes', kw['HashKnownHosts'])

    def test_ignore_comments_and_spaces(self):
        config = textwrap.dedent('''\
        # Host myhost.net
        # user auser
        

        Host myhost.com myhost.org

        #preferredauthentications publickey
        preferredauthentications password
        user myuser

        # forwardagent no

        host *
        forwardagent yes

        ''')
        ssh_config = pysshconfig.loads(config)
        self.assertEqual({'forwardagent': 'yes'}, ssh_config.get('myhost.net'))
        self.assertEqual('yes', ssh_config.get('myhost.com')['forwardagent'])


if __name__ == '__main__':
    unittest.main(verbosity=2)

"""
    pyvk.auth
    ~~~~~~~~~

    Implements VK authentication and cookie storage.

    :copyright: (c) 2013-2016, Max Kuznetsov
    :license: MIT, see LICENSE for more details.
"""

from __future__ import generators, with_statement, print_function, \
    unicode_literals, absolute_import

from .utils import PY2

import os
import time
import lxml.html
import requests
import pickle
import binascii
import logging
from appdirs import AppDirs
from requests.exceptions import RequestException

from .config import AuthConfig
from .exceptions import AuthError, PyVKError
from .utils import Prompt
from injector import Module, Key, provides, Injector, inject, singleton


if PY2:
    from urlparse import urlparse, ParseResult, parse_qs
    from urllib import urlencode
else:
    from urllib.parse import urlparse, ParseResult, parse_qs, urlencode


logger = logging.getLogger(__name__)
logging.getLogger('requests').setLevel(logging.WARNING)


class Auth(object):

    def __init__(self, api_id, config):
        self.config = config
        self.api_id = api_id

        self.http = requests.Session()
        self.username = None
        self.token = None
        self.scope = self.config.scope

        # ---------------------------------------------------------------------

        if config.token:
            logger.debug('Testing the token provided...')
            try:
                self.scope = self.test_token(config.token)

            except PyVKError as e:
                raise AuthError('Invalid token', **e.attrs)

            else:
                logger.debug('Token is valid.')
                self.token = config.token
                return

        # ---------------------------------------------------------------------

        self._state = None

        self.username = config.username
        if not self.username:
            logger.debug('Username is not provided. Awaiting input...')
            self.username = self.config.prompt.ask_username()

        if not self.config.disable_cache:
            logger.debug('Reading authorisation cache')

            self.cache = Cache(self.username)
            cached = self.cache.read()

            if cached:
                cookies = cached.get('cookies', {})
                self.http.cookies.update(cookies)

                # set() added for PY2 compatibility.
                assert {'token_time', 'scope', 'token'} <= set(cached.keys())

                # Age of the cached token
                time_diff = int(time.time()) - cached['token_time']

                # For the cached token to be valid it has to have the same mask
                # as requested and age less than expiration time.
                if time_diff < 24 * 3600 and self.scope <= cached['scope']:
                    logger.debug('Testing the cached token...')
                    try:
                        self.scope = self.test_token(cached['token'])
                    except PyVKError:
                        pass
                    else:
                        logger.debug('Cached token is valid.')
                        self.token = cached['token']
                else:
                    logger.debug('Cached token is expired or do not match '
                                 'requested permissions.')
            else:
                logger.debug('Cache is empty.')
        else:
            logger.debug('Cache is disabled. Authorisation needed.')

    @staticmethod
    def test_token(token):
        r = requests.get('https://api.vk.com/method/account.getAppPermissions'
                         'access_token=%s' % token)
        try:
            return r.json()['response']
        except Exception:
            return None

    def auth(self):

        self._state = 'auth_page'
        args = ()

        while self._state != 'exit':

            logger.debug('Auth stage: %s' % self._state)
            fname = '_s_%s' % self._state

            assert hasattr(self, fname), 'State `%s\' not in DFA!' % self._state

            f = getattr(self, fname)

            # Cannot use pattern matching due to PY2 compatibility.
            result = f(*args)
            self._state = result[0]
            args = result[1:]

    # --------------------------------------------------------------------------

    def _s_auth_page(self):

        exc_data = {'state': self._state}

        q = {'client_id': self.api_id, 'scope': self.scope,
             'redirect_uri': 'https://oauth.vk.com/blank.html',
             'display': 'mobile', 'v': self.config.version,
             'response_type': 'token'}

        auth_url = 'https://oauth.vk.com/authorize?%s' % urlencode(q)

        # Start auth URL
        try:
            r = self.http.get(auth_url, timeout=self.config.timeout)
        except RequestException as e:
            raise AuthError('Network error', exc=e, **exc_data)

        url = urlparse(r.url)

        # Token page
        if url.fragment.startswith('access_token='):
            return ('get_token', url)

        # Error page, try to repeat with empty cookies
        elif 'err' in url.path:
            logger.info('Cookies corrupted, trying to repeat...')
            self.http.cookies.clear()
            return ('auth_page', )

        else:
            # TODO: fix the ugly parsing
            doc = lxml.html.document_fromstring(r.text.encode('utf-8'))
            form = doc.forms[0]
            action_url = urlparse(form.action)
            act = parse_qs(action_url.query)['act'][0]

            if act == 'login':
                return ('login', form.action, dict(form.fields))
            elif act == 'grant_access':
                return ('grant_access', form.action)
            else:
                raise AuthError('Unknown form action on auth page',
                                response=r, **exc_data)

    def _s_login(self, action_url, fields):

        exc_data = {'state': self._state, 'action_url': action_url,
                    'fields': fields}

        # Collect post data from the form and fill user-defined fields
        post_data = fields
        post_data['email'] = self.username
        post_data['pass'] = self.config.prompt.ask_password()

        try:
            r = self.http.post(action_url, data=post_data,
                               timeout=self.config.timeout)
        except RequestException as e:
            raise AuthError('Network error', exc=e, **exc_data)

        doc = lxml.html.document_fromstring(r.text.encode('utf-8'))

        # Check for wrong password
        errors = doc.find_class('service_msg_warning')

        if errors:
            raise AuthError('Wrong email or password', msg=errors[0].text,
                            response=r, **exc_data)

        url = urlparse(r.url)

        # Token page
        if url.fragment.startswith('access_token='):
            return ('get_token', url)

        # Otherwise: check the need to confirm access
        form = doc.forms[0]
        action_url = urlparse(form.action)
        act = parse_qs(action_url.query)['act'][0]

        if act == 'grant_access':
            return ('grant_access', form.action)

        elif act == 'authcheck_code':
            action_url = '%s://%s%s' % (url.scheme, url.netloc, form.action)
            return ('authcheck', action_url, dict(form.fields))

        else:
            raise AuthError('Unknown form action on login page.',
                            response=r, **exc_data)

    def _s_authcheck(self, action_url, fields):

        exc_data = {'state': self._state, 'action_url': action_url,
                    'fields': fields}

        if not all(k in fields for k in ('remember', 'code')):
            raise AuthError('Authcheck page has unexpected formatting.',
                            **exc_data)

        fields['remember'] = 0
        fields['code'] = self.config.prompt.ask_secret_code()

        try:
            r = self.http.post(action_url, data=fields,
                               timeout=self.config.timeout)
        except RequestException as e:
            raise AuthError('Network error', exc=e, **exc_data)

        doc = lxml.html.document_fromstring(r.text.encode('utf-8'))

        # Check for wrong password
        errors = doc.find_class('service_msg_warning')

        if errors:
            raise AuthError('Wrong secret code',
                            msg=errors[0].text, response=r, **exc_data)

        url = urlparse(r.url)

        # Token page
        if url.fragment.startswith('access_token='):
            return ('get_token', url)

        # Otherwise: check the need to confirm access
        form = doc.forms[0]
        action_url = urlparse(form.action)
        act = parse_qs(action_url.query)['act'][0]

        if act == 'grant_access':
            return ('grant_access', form.action)

        else:
            raise AuthError('Unknown form action on authcheck page.',
                            response=r, **exc_data)

    def _s_grant_access(self, action_url):

        exc_data = {'state': self._state, 'action_url': action_url}

        try:
            r = self.http.post(action_url, timeout=self.config.timeout)
        except RequestException as e:
            raise AuthError('Network error', exc=e, **exc_data)

        url = urlparse(r.url)

        # Token page
        if url.fragment.startswith('access_token='):
            return ('get_token', url)

        else:
            raise AuthError('Token fetch URL is not found', url=url, **exc_data)

    def _s_get_token(self, url):

        assert isinstance(url, ParseResult)

        # Final token
        self.token = parse_qs(url.fragment)['access_token'][0]

        if not self.config.disable_cache:
            self.cache.write(token=self.token, scope=self.scope,
                             token_time=int(time.time()),
                             cookies=self.http.cookies.get_dict())
        return ('exit', )


class Cache(object):

    def __init__(self, username):

        cache_dir = AppDirs('pyvk').user_cache_dir

        if not os.path.exists(cache_dir):
            # `exist_ok' is not used for compatibility.
            os.makedirs(cache_dir)

        cache_hash = binascii.crc32(username.encode('utf-8'))
        self.file = os.path.join(cache_dir, str(cache_hash))

    def read(self):
        try:
            with open(self.file, 'rb') as cf:
                return pickle.load(cf)

        except (OSError, IOError, EOFError, pickle.PickleError):
            # Auth cache is corrupted or unreadable, start with an empty cache
            return {}

    def write(self, **data):
        with open(self.file, 'wb') as cf:
            pickle.dump(data, cf, protocol=2)

"""
    pyvk.request
    ~~~~~~~~~~~~

    Implements VK API request object ready to be sent.

    :copyright: (c) 2013-2016, Max Kuznetsov
    :license: MIT, see LICENSE for more details.
"""

from __future__ import generators, with_statement, print_function, \
    unicode_literals, absolute_import

import requests
import logging
from requests.exceptions import RequestException
from time import sleep
from injector import Module, Key, provides, Injector, inject, singleton, AssistedBuilder

from .utils import PY2
from .auth import Auth
from .auth import Auth
from .config import RequestConfig, AuthConfig
from .exceptions import ReqError, APIError, AuthError

if PY2:
    from urllib import urlencode
else:
    from urllib.parse import urlencode

logger = logging.getLogger(__name__)
logging.getLogger('requests').setLevel(logging.WARNING)


@inject(_auth=Auth, _config=RequestConfig)
class Request(object):
    def __init__(self, method, args):
        self._method = method

        # Transform lists into comma-separated strings
        self._args = {k: ','.join(str(i) for i in v) if type(v) is list else v
                      for k, v in args.items()}

    def _fetch_response(self):

        args = self._args.copy()
        args['access_token'] = self._auth.token
        args['v'] = args.get('v', self._config.version)

        url = 'https://api.vk.com/method/%s?%s' \
              % (self._method, urlencode(args))

        # 1. Send HTTP request
        try:
            response = requests.get(url, timeout=self._config.timeout)
            logger.debug('GET %s' % url)

        except RequestException as e:
            raise ReqError('Network error', exc=e)

        # 2. Unpack it
        try:
            data = response.json()

        except ValueError as e:
            raise ReqError('Response is not a valid JSON',
                           response=response, exc=e)
        assert isinstance(data, dict)

        # 3. Try to return the result
        try:
            return data['response']

        except KeyError:
            if not self._config.error_handling:
                return data

        # 4. Handle possible API error response
        try:
            err = data['error']
            raise APIError('VK API returned an error', code=err['error_code'],
                           msg=err['error_msg'], error=err, response=response)

        except KeyError as e:
            raise ReqError('Error response from API is malformed',
                           response=response, data=data, exc=e)

    def send(self):

        for attempt in range(self._config.max_attempts):
            try:
                return self._fetch_response()

            except APIError as e:
                # User authorisation failed, try to reauthorise.
                if (e.code == 5 or e.code == 10) and self._config.auto_reauth:

                    logger.info('It seems that current token is unavailable '
                                'now. Trying to renew...')
                    try:
                        self._auth.auth()

                    except AuthError as e:
                        raise ReqError('Could not renew token',
                                       exc=e, attempt=attempt)

                    else:
                        assert self._auth.token
                        self._args['access_token'] = self._auth.token

                        logger.info('Access token succesfully renewed, '
                                    'repeating the request...')

                # Requests are too ofter.
                elif e.code in (6, 9):
                    t = 0.3 * (attempt + 1)
                    logger.info('Too many requests per second. '
                                'Wait %.1f sec and retry.' % t)
                    sleep(t)

                # Captcha needed.
                elif e.code == 14:
                    try:
                        self._args['captcha_sid'] = e.error['captcha_sid']
                        img = e.error['captcha_img']

                    except KeyError:
                        raise ReqError('Captcha is required, server response'
                                       'is malformed', exc=e)

                    else:
                        key = self._config.prompt.ask_captcha(img)
                        self._args['captcha_key'] = key

                # Don't handle error, raise it as is.
                else:
                    raise

        raise ReqError('Request failed after all attempts.')


@inject(auth=Auth, request=AssistedBuilder(Request))
class RequestHandler(object):

    def __init__(self, prefix, config):
        self._config = config
        self._prefix = prefix or []

        self.handler = Injector([])

    def __getattr__(self, suffix):
        return RequestHandler(self._prefix + [suffix])

    def __call__(self, **args):
        return self.request.build(method=self.method_name(),
                                  args=args).send()

    def __repr__(self):
        return '<RequestHandler | prefix=%s>' % repr(self.method_name())

    def method_name(self):
        return '.'.join(self._prefix)


class RequestHandlerBuilder(Module):
    @provides(RequestHandler)
    @inject(auth=Auth)
    def get_handler(self, auth):
        return RequestHandler()

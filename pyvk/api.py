"""
    pyvk.api
    ~~~~~~~~

    Defines classes for VK API public interface, requests, and authorisation.

    :copyright: (c) 2013-2016, Max Kuznetsov
    :license: MIT, see LICENSE for more details.
"""

from __future__ import generators, with_statement, print_function, \
    unicode_literals, absolute_import

import logging

from .config import RequestConfig, AuthConfig, GlobalConfig
from .auth import Auth
from .request import RequestHandler
from injector import Module, Key, provides, Injector, inject, singleton, AssistedBuilder

logger = logging.getLogger(__name__)


class API(object):
    def __init__(self, api_id, **kwargs):
        self._config = GlobalConfig(**kwargs)

        log_file = {'filename': self._config.log_file} \
            if self._config.log_file else {}

        logging.basicConfig(format=self._config.log_format,
                            level=self._config.log_level,
                            **log_file)

        self._auth = Auth(self.api_id, AuthConfig(**kwargs))

        self.inject = Injector([APIModule(api_id, )])

    def request(self, **kwargs):
        builder = self.inject.get(AssistedBuilder(RequestHandler))
        return builder.build(prefix=[], config=RequestConfig(**kwargs))

    def __repr__(self):
        auth = self.inject.get(Auth)
        return '<VK API | id=%d>' % auth.api_id


class APIModule(Module):
    def __init__(self, api_id, config):
        self.api_id = api_id
        self.config = config

    @singleton
    @provides(Auth)
    def get_auth(self):
        return
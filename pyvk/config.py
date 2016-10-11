# -*- coding: utf-8 -*-
"""
    pyvk.config
    ~~~~~~~~~~~~~

    Defines constants, parameters, and their default values.

    :copyright: (c) 2013-2016 by Max Kuznetsov.
    :license: MIT, see LICENSE for more details.
"""

import logging
from .utils import Prompt


p_notify = 1
p_friends = 2
p_photos = 4
p_audio = 8
p_video = 16
p_offers = 32
p_questions = 64
p_pages = 128
p_leftmenu = 256
p_status = 1024
p_notes = 2048
p_messages = 4096
p_wall = 8192
p_ads = 32768
p_offline = 65536
p_docs = 131072
p_groups = 262144
p_notifications = 524288
p_stats = 1048576
p_email = 4194304
p_market = 134217728


p_all = p_notify | p_friends | p_photos | p_audio | p_video \
    | p_offers | p_questions | p_pages | p_leftmenu | p_status \
    | p_notes | p_messages | p_wall | p_ads | p_offline | p_docs \
    | p_groups | p_notifications | p_stats | p_email | p_market


p_basic = p_friends | p_photos | p_audio | p_video | p_status | p_messages \
    | p_wall | p_groups


class Config:
    _lock = False

    def __init__(self, **params):
        for attr, value in params.items():
            setattr(self, attr, value)

        # Make attributes read-only
        self._lock = True

    def __setattr__(self, attr, value):
        if self._lock:
            raise AttributeError('Cannot assign attributes to this class')

        if attr in dir(self):
            self.__dict__[attr] = value

        # Ignore undefined parameters
        else:
            pass


class GlobalConfig(Config):
    log_format = '%(asctime)s %(name)s %(levelname)s: %(message)s'  # type: str
    log_level = logging.INFO    # type: int
    log_file = None             # type: str
    prompt = Prompt             # type: Prompt

    timeout = 6.05      # type: float
    version = '5.52'    # type: str


class AuthConfig(GlobalConfig):
    scope = p_basic         # type: int
    disable_cache = False   # type: bool
    token = None            # type: str
    username = None



class RequestConfig(GlobalConfig):
    auto_reauth = True  # type: bool
    slow_down = False   # type: bool
    max_attempts = 5    # type: int
    error_handling = True,                          # type: bool
    user_agent = 'Mozilla/5.0(Windows NT 6.1; WOW64; rv:22.0)' \
                 'Gecko/20100101 Firefox/22.0'      # type: str

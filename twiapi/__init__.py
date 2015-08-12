from __future__ import print_function, absolute_import
import pycurl, urllib, json
import base64, random, hmac
from time import time
from hashlib import sha1

class Buffer(object):

    def __init__(self, apiclient, callback, callback_param=None):
        self.buf = ''
        self.apiclient = apiclient
        self.callback = callback
        self.callback_param = callback_param

    def feed(self, data):
        self.buf += data
        if data.endswith('\n'):
            try:
                self.callback(json.loads(self.buf),
                              self.apiclient, self.callback_param)
            except ValueError:
                pass
            self.buf = ''


class Credentials(object):

    def __init__(self, consumer_key, consumer_secret, access_token, access_token_secret):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.access_token = access_token
        self.access_token_secret = access_token_secret


class Client(object):

    def __init__(self, credentials, debug=True):
        self.credentials = credentials
        self.debug = debug

    @staticmethod
    def _nonce():
        return '{0}h'.format(base64.b64encode(str(random.random())))

    @staticmethod
    def _time():
        return str(int(time()))

    @staticmethod
    def urlencode(string):
        return urllib.quote(string, '')

    @classmethod
    def _urlify(cls, params):
        return '&'.join(sorted(['{0}={1}'.format(cls.urlencode(key),
                                                 cls.urlencode(value)) \
                                for key, value in params.items()]))

    @classmethod
    def _headerify(cls, params):
        return ', '.join(sorted(['{0}="{1}"'.format(cls.urlencode(key),
                                                    cls.urlencode(value)) \
                                for key, value in params.items()]))

    @classmethod
    def _argstring(cls, params, oauth_params):
        sigparams = {}
        sigparams.update(params)
        sigparams.update(oauth_params)
        return cls._urlify(sigparams)

    @classmethod
    def _signkey(cls, credentials):
        return '&'.join((cls.urlencode(credentials.consumer_secret),
                         cls.urlencode(credentials.access_token_secret)))

    @staticmethod
    def _hmac_signature(bstring, key):
        hashed = hmac.new(key, bstring, sha1)
        return hashed.digest().encode('base64').rstrip('\n')

    @staticmethod
    def default_callback(data, apiclient, callback_param):
        print(data)

    def oauth_params(self, method, url, params):
        oauth_params = {
            'oauth_consumer_key': self.credentials.consumer_key,
            'oauth_nonce': self._nonce(),
            'oauth_timestamp': self._time(),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_token': self.credentials.access_token,
            'oauth_version': '1.0',
        }

        bstring = '&'.join([method.upper(),
                            self.urlencode(url),
                            self.urlencode(self._argstring(params,
                                                            oauth_params))])

        signkey = self._signkey(self.credentials)
        signature = self._hmac_signature(bstring, signkey)

        oauth_params.update({'oauth_signature': signature})

        return oauth_params

    def query(self, method, url, params, callback=None, callback_param=None):
        method = method.upper()
        if method not in ('GET', 'POST'):
            raise Exception('unsupported method')

        oauth_params = self.oauth_params(method, url, params)

        conn = pycurl.Curl()

        if callback is not None:
            buf = Buffer(self, callback, callback_param)
            conn.setopt(pycurl.WRITEFUNCTION, buf.feed)

        if self.debug is True:
            conn.setopt(pycurl.VERBOSE, True)

        if method == 'GET':
            conn.setopt(pycurl.URL, '{0}?{1}'.format(url, self._urlify(params)))
        else:
            conn.setopt(pycurl.URL, url)
            conn.setopt(pycurl.POSTFIELDS, self._urlify(params))

        conn.setopt(pycurl.HTTPHEADER,
                    ['Authorization: OAuth {0}'.format(self._headerify(oauth_params))])

        return conn.perform()


    def tweet(self, status):
        self.query('POST', 'https://api.twitter.com/1.1/statuses/update.json',
                   {'status': str(status)}, self.default_callback)

    def retweet(self, tid):
        self.query('POST', 'https://api.twitter.com/1.1/statuses/retweet/{0}.json'.format(tid),
                   {'id': str(tid)}, self.default_callback)

    def follow(self, screen_name):
        self.query('POST', 'https://api.twitter.com/1.1/friendships/create.json',
                   {'screen_name': str(screen_name), 'follow': 'true'}, self.default_callback)

    def stream(self, params, callback, callback_params=None):
        self.query('POST', 'https://stream.twitter.com/1.1/statuses/filter.json',
                   params, callback, callback_params)

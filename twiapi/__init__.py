import pycurl, urllib, json
import base64, random, hmac
from time import time
from hashlib import sha1

class ApiClient(object):

    def __init__(self, credentials):
        self.credentials = credentials

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


class StreamClient(ApiClient):

    def __init__(self, credentials):
        ApiClient.__init__(self, credentials)
        self.url = 'https://stream.twitter.com/1.1/statuses/filter.json'
        self.buf = ''

    def _bufferize(self, data):
        self.buf += data
        if data.endswith('\n'):
            try:
                self.callback(json.loads(self.buf))
            except ValueError:
                pass
            self.buf = ''

    def run(self, params, callback):
        self.callback = callback
        oauth_params = self.oauth_params('POST', self.url, params)
        conn = pycurl.Curl()
        conn.setopt(pycurl.VERBOSE, True)
        conn.setopt(pycurl.URL, self.url)
        conn.setopt(pycurl.WRITEFUNCTION, self._bufferize)
        conn.setopt(pycurl.POSTFIELDS, self._urlify(params))
        conn.setopt(pycurl.HTTPHEADER, ['Authorization: OAuth {0}'.format(self._headerify(oauth_params))])
        conn.perform()


class Credentials(object):

    def __init__(self, consumer_key, consumer_secret, access_token, access_token_secret):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.access_token = access_token
        self.access_token_secret = access_token_secret

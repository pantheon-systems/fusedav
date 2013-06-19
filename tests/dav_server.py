import os
import sys
import logging

from multiprocessing import Process

from pywebdav.server import server
from pywebdav.server.fileauth import DAVAuthHandler

PYWEBDAV_HOST = '127.0.0.1'
PYWEBDAV_PORT = '8008'

class DavServer:
    def __init__(self, path):
        self.path = path

    def start(self):
        self.t = Process(target=self.run)
        self.t.start()

    def stop(self):
        self.t.terminate()
        self.t.join()

    def run(self):
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')
        conf = server.setupDummyConfig(**{
            'verbose': False,
            'directory': self.path,
            'port': PYWEBDAV_PORT,
            'host': PYWEBDAV_HOST,
            'noauth': True,
            'user': '',
            'password': '',
            'daemonize': False,
            'daemonaction': 'start',
            'counter': 0,
            'lockemulation': False,
            'mimecheck': True,
            'chunked_http_response': True,
            'http_request_use_iterator': 0,
            'http_response_use_iterator': True,
            'baseurl': 0
        })
        handler = DAVAuthHandler
        handler._config = conf
        logging.getLogger().setLevel(logging.ERROR)
        server.runserver(directory=self.path, noauth=True, handler=handler)

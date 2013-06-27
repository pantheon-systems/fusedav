# This file is part of fusedav.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import unittest
import tempfile
import subprocess
import os
import shutil
import logging
import time
import sys

from sh import cp, mv

from multiprocessing import Process
from pywebdav.server import server
from pywebdav.server.fileauth import DAVAuthHandler

# You can execute this test by executing:
#   cd to your /opt/<fusedav> directory and execute 'trial ./tests/test_dav.py'
#   cd to any directory and execute 'FUSEDAV_PATH=<path to fusedav binary> trial <path to test_dav.py>
# You can add 'LOG_LEVEL=<level, e.g. debug> at the beginning of the line, e.g.
#   LOG_LEVEL=debug [FUSEDAV_PATH=<path to fusedav binary>] trial <path to test_dav.py>

log = logging.getLogger('test_dav')
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'error')

if LOG_LEVEL == 'debug':
    log.setLevel(logging.DEBUG)
elif LOG_LEVEL == 'info':
    log.setLevel(logging.INFO)
elif LOG_LEVEL == 'warning':
    log.setLevel(logging.WARNING)
else:
    log.setLevel(logging.ERROR)

# if FUSEDAV_PATH is specified, use it. It must point to an executable file. (If the file
# is executable but is not a fusedav binary, weird things will happen);
# otherwise, assume we are in an /opt/fusedav{version} directory where
# we want to find the binary <cwd>/src/fusedav
if 'FUSEDAV_PATH' in os.environ:
    fusedav_binary = os.environ.get('FUSEDAV_PATH')
    if os.path.isfile(fusedav_binary) and os.access(fusedav_binary, os.X_OK):
        print "Using FUSEDAV_PATH's ", fusedav_binary
    else:
        exitstring = 'FUSEDAV_PATH specified but ' + fusedav_binary + ' is not executable'
        sys.exit(exitstring)
else:
    fusedav_binary = os.path.join(os.getcwd(), 'src', 'fusedav')
    if os.path.isfile(fusedav_binary) and os.access(fusedav_binary, os.X_OK):
        # As soon as 'setUp' is called, the cwd will be, e.g., /opt/fusedav/_trial_temp, so
        # './src/fusedav' will no longer work. Get the cwd at this point in order to have the
        # correct path
        print "Using current directory's ", fusedav_binary
    else:
        exitstring = fusedav_binary + ' is not executable'
        sys.exit(exitstring)

DAV_CLIENT = 'fusedav'

# if we set nodaemon, we can use the pid we get on open to cleanup on close
# REVIEW: would this affect basic functionality?
# NB: this config is really for the upcoming new version of fusedav with a config file
FUSEDAV_CONFIG = 'nodaemon,noexec,atomic_o_trunc,hard_remove,umask=0007,cache_path='

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

class TestDav(unittest.TestCase):
    files_root = None
    config_file = None
    mount_point = None
    dav_directory = None
    fuseprocess = None

    def setUp(self):
        log.debug('Testing client: {0}'.format(DAV_CLIENT))
        # make temp dir
        self.files_root = tempfile.mkdtemp() + '/'
        log.debug('File root: {0}'.format(self.files_root))

        # start server with temp dir
        self.dav_server = DavServer(self.files_root)
        self.dav_server.start()

        self.mount_point = tempfile.mkdtemp() + '/'
        log.debug('Mount point: {0}'.format(self.mount_point))

        dav_url = 'http://{0}:{1}/'.format(PYWEBDAV_HOST, PYWEBDAV_PORT)
        log.debug('Dav url: {0}'.format(dav_url))

        self.cache_dir = tempfile.mkdtemp()
        log.debug('Cache dir: {0}'.format(self.cache_dir))
        config = FUSEDAV_CONFIG + self.cache_dir

        command = [ fusedav_binary, dav_url, self.mount_point, '-o', config]
        log.debug('Executing: ' + ' '.join(command))
        # open such that we can get the process id
        self.fuseprocess = subprocess.Popen(command, shell=False)
        log.debug('pid is ' + str(self.fuseprocess.pid))

        self.dav_directory = DavDirectory(self.mount_point, self.files_root)

        time.sleep(3)

    def test_propfind(self):
        self.dav_directory.put_file('test1.txt', 'test 1 content')
        listing = self.dav_directory.get_dav_listing('')
        log.debug(listing)

        self.assertEqual(set(os.listdir(self.files_root)), listing)

    def test_put(self):
        path = 'test1.txt'
        content = 'test 1 content'
        self.dav_directory.put_file(path, content)
        listing = self.dav_directory.get_listing('')
        log.debug(listing)

        self.assertEqual(set(os.listdir(self.files_root)), listing)
        self.assertEqual(self.dav_directory.get_real_file(path), content)

    def test_get(self):
        path = 'test1.txt'
        content = 'test'

        self.dav_directory.put_file(path, content)

        self.assertEqual(self.dav_directory.get_real_file(path), content)
        self.assertEqual(self.dav_directory.get_file(path), content)

    def test_mkdir(self):
        paths = ['testdir1', 'testdir2', 'testdir1/testdir3']

        map(self.dav_directory.mkdir, paths)

        self.assertEqual(self.dav_directory.get_listing(''), {'testdir1', 'testdir2'})
        self.assertEqual(self.dav_directory.get_listing('testdir1'), {'testdir3'})

    def test_copy_file(self):
        source = 'test_src.txt'
        dest = 'test_dest.txt'
        content = 'copy content'

        self.dav_directory.put_file(source, content)
        self.dav_directory.copy(source, dest)

        self.assertEqual(self.dav_directory.get_listing('/'), {source, dest})
        self.assertEqual(self.dav_directory.get_file(source), content)
        self.assertEqual(self.dav_directory.get_real_file(dest), content)
        self.assertEqual(self.dav_directory.get_file(dest), content)

    def test_copy_dir(self):
        source = 'test1'
        dest = 'test2'

        file1 = 'test1/file1'
        file2 = 'test1/file2'

        content = 'copy content'

        self.dav_directory.mkdir(source)
        self.dav_directory.put_file(file1, content)
        self.dav_directory.put_file(file2, content)

        self.dav_directory.copy(source, dest, dir=True)

        self.assertEqual(self.dav_directory.get_listing(''), {source, dest})
        self.assertEqual(self.dav_directory.get_listing('test1'), {'file1', 'file2'})
        self.assertEqual(self.dav_directory.get_listing('test2'), {'file1', 'file2'})

    def test_mv_file(self):
        source = 'test_src.txt'
        dest = 'test_dest.txt'
        content = 'mv content'

        self.dav_directory.put_file(source, content)
        self.dav_directory.mv(source, dest)

        self.assertEqual(self.dav_directory.get_listing(''), {dest})
        self.assertEqual(self.dav_directory.get_file(dest), content)

    def tearDown(self):
        time.sleep(1)
        log.debug("Trying to remove mount directory {0}".format(self.mount_point))
        try:
            command = [ 'fusermount', '-uz', self.mount_point ]
            subprocess.Popen(command, shell=False)
        except Exception as e:
            print "Exception: ", e

        shutil.rmtree(self.cache_dir)
        shutil.rmtree(self.files_root)

        self.dav_server.stop()
        # ignore errors on removing files in directory
        shutil.rmtree(self.mount_point, True)

        subprocess.Popen.kill(self.fuseprocess)
        log.debug("Process ({0}) terminated; Directory removed {1}".format(self.fuseprocess.pid, self.mount_point))


class DavDirectory:
    def __init__(self, mount_point, files_root):
        self.mount_point = mount_point
        self.files_root = files_root

    def get_listing(self, path):
        listing = os.listdir(self.mount_point + path)
        log.debug("Listing from '{0}': {1}".format(path, listing))
        return set(listing)

    def get_dav_listing(self, path):
        listing = os.listdir(self.mount_point + path)

        try:
            listing.remove('lost+found')
        except ValueError:
            pass

        log.debug("Listing from '{0}': {1}".format(path, listing))
        return set(listing)

    def mkdir(self, path):
        p = self.mount_point + path
        log.debug("Making directory: {0}".format(path))
        os.mkdir(p)

    def copy(self, source, dest, dir=False):
        s = self.mount_point + source
        d = self.mount_point + dest
        log.debug("Copying from '{0}' to '{1}'".format(s, d))
        if dir:
            cp('-r', s, d)
        else:
            cp(s, d)
        time.sleep(1)

    def mv(self, source, dest):
        s = self.mount_point + source
        d = self.mount_point + dest
        log.debug("Moving from from '{0}' to '{1}'".format(s, d))
        mv(s, d)

    def put_file(self, path, content):
        p = self.mount_point + path
        log.debug("Putting file at '{0}' with: {1}".format(p, content))
        f = open(p, 'w')
        f.write(content)
        f.close()

    def get_file(self, path):
        p = self.mount_point + path
        f = open(p, 'r')
        content = f.read()
        f.close()
        log.debug("Reading from '{0}': {1}".format(p, content))
        return content

    def get_real_file(self, path):
        p = self.files_root + path
        f = open(p, 'r')
        content = f.read()
        f.close()
        log.debug("Reading from '{0}': {1}".format(p, content))
        return content

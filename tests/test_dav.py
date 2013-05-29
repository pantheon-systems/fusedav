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
import signal

from sh import cp, mv

from titan.pantheon.tests.lib.dav_server import DavServer, PYWEBDAV_HOST, PYWEBDAV_PORT

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

DAV_CLIENT = 'fusedav'

FUSEDAV_CONFIG = 'nodaemon,noexec,atomic_o_trunc,' +\
                 'hard_remove,umask=0007,cache_path='


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

        # The current working directory is <dir we started in>/_trial_temp,
        # so use ".." to find "src/fusedav"
        command = [ '../src/fusedav', dav_url, self.mount_point, '-o', config]
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
        self.dav_directory.put_file('test1.txt', 'test 1 content')
        listing = self.dav_directory.get_listing('')
        log.debug(listing)

        self.assertEqual(set(os.listdir(self.files_root)), listing)

    def test_get(self):
        path = 'test1.txt'
        content = 'test'

        self.dav_directory.put_file(path, content)

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
        log.debug("Trying to remove directory {0}".format(self.mount_point))
        for x in xrange(5):
            try:
                #subprocess.call(['umount', self.mount_point])
                command = [ 'fusermount', '-uz', self.mount_point ]
                subprocess.Popen(command, shell=False)
                os.kill(self.fuseprocess.pid, signal.SIGTERM)
                #log.debug("Process ({0}) terminated; Directory removed {1}".format(self.fuseprocess.pid, self.mount_point))
                # os.rmdir(self.mount_point)
                shutil.rmtree(self.mount_point)
                break
            except Exception as e:
                print e
                time.sleep(1)
        else:
            log.error("Unable to safely remove: {0}".format(self.mount_point))

        self.dav_server.stop()

        shutil.rmtree(self.cache_dir)
        shutil.rmtree(self.files_root)


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

import unittest
import os
import shutil
import logging
import subprocess
from sh import cp, mv, rm, echo, touch
import time

from titan.pantheon import logger

log = logger.getLogger(__name__)
log.setLevel(logging.DEBUG)

class TestStress(unittest.TestCase):
    def setUp(self):
        log.debug('setUp')

    def tearDown(self):
        log.debug("tearDown")

    def test_all(self):
        log.debug(subprocess.check_output(["/bin/make",  "-f", "/opt/fusedav/tests/Makefile",  "-i",  "all"]))


    #def test_a_cltest(self, i=256):
        #arg1 = "-i" + str(i)
        #log.debug(subprocess.check_output(["/opt/fusedav/tests/cltest.sh", arg1]))

    #def test_b_statcacheprune(self, d=4, f=64):
        #arg1 = "-d" + str(d)
        #arg1 = "-f" + str(f)
        #log.debug(subprocess.check_output(["/opt/fusedav/tests/cltest.sh", arg1, arg2]))

    #def test_f_iozone(self, g=65536, n=64):
        #arg1 = "-g" + str(g)
        #arg2 = "-n" + str(n)
        #log.debug(subprocess.check_output(["/opt/iozone/src/current/iozone", "-Ra", arg1, arg2]))


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestStress)
    unittest.TextTestRunner(verbosity=2).run(suite)

import unittest
import logging
import subprocess

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


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestStress)
    unittest.TextTestRunner(verbosity=2).run(suite)

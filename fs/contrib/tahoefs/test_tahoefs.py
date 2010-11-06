#!/usr/bin/python
"""
    Test the TahoeFS
    
    @author: Marek Palatinus <marek@palatinus.cz>
"""

import sys
import logging
import unittest

from fs.base import FS
import fs.errors as errors
from fs.tests import FSTestCases, ThreadingTestCases
from fs.contrib.tahoefs import TahoeFS, Connection

logging.getLogger().setLevel(logging.DEBUG)
logging.getLogger('fs.tahoefs').addHandler(logging.StreamHandler(sys.stdout))

WEBAPI = 'http://pubgrid.tahoe-lafs.org'

class TestTahoeFS(unittest.TestCase,FSTestCases,ThreadingTestCases):

    #  Disabled by default because it takes a *really* long time.
    __test__ = False

    def setUp(self):
        self.dircap = TahoeFS.createdircap(WEBAPI)
        self.fs = TahoeFS(self.dircap, timeout=0, webapi=WEBAPI)
             
    def tearDown(self):
        self.fs.close()
         
    def test_dircap(self):
        # Is dircap in correct format?
        self.assert_(self.dircap.startswith('URI:DIR2:') and len(self.dircap) > 50)
     
    def test_concurrent_copydir(self):
        #  makedir() on TahoeFS is currently not atomic
        pass

    def test_makedir_winner(self):
        #  makedir() on TahoeFS is currently not atomic
        pass
    
    def test_big_file(self):
        pass

if __name__ == '__main__':
    unittest.main()

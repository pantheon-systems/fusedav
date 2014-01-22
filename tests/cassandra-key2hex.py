#! /usr/bin/env python

import binascii
import sys

key = binascii.hexlify(sys.argv[1]);
print key;

import unittest
from pgpy import PGPKey

class TestClass(unittest.TestCase):
    def test_keyLengthRSAShort(self):
        key = PGPKey.from_file('keys/key1.pgp')
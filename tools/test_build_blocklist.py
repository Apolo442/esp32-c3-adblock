import pathlib
import subprocess
import sys
import tempfile
import unittest

from build_blocklist import HASH_BYTES, covered_by_parent, fnv


class BuildBlocklistTests(unittest.TestCase):
    def test_hosts_line_includes_every_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'hosts'
            output = root / 'blocklist.bin'
            source.write_text('0.0.0.0 ads.example.com tracker.example.com # comment\n'
                              '127.0.0.1 metrics.example.com\n', encoding='utf-8')

            subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('build_blocklist.py')),
                            str(output), str(source)], check=True, capture_output=True, text=True)

            data = output.read_bytes()
            hashes = {int.from_bytes(data[i:i + HASH_BYTES], 'little')
                      for i in range(0, len(data), HASH_BYTES)}
            expected = {fnv(domain.encode()) for domain in
                        ('ads.example.com', 'tracker.example.com', 'metrics.example.com')}
            self.assertEqual(hashes, expected)

    def test_subdomains_of_a_listed_domain_are_dropped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'hosts'
            output = root / 'blocklist.bin'
            source.write_text('0.0.0.0 example.com ads.example.com a.b.example.com\n'
                              '0.0.0.0 ads.example.org\n'
                              'com\n', encoding='utf-8')

            subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('build_blocklist.py')),
                            str(output), str(source)], check=True, capture_output=True, text=True)

            data = output.read_bytes()
            hashes = {int.from_bytes(data[i:i + HASH_BYTES], 'little')
                      for i in range(0, len(data), HASH_BYTES)}
            self.assertEqual(hashes, {fnv(b'example.com'), fnv(b'ads.example.org')})

    def test_bare_tld_never_covers_a_domain(self):
        # The firmware stops before the TLD, so an entry like "co.uk" still covers its children
        # but a one-label name cannot.
        self.assertFalse(covered_by_parent('example.com', {'com'}))
        self.assertTrue(covered_by_parent('ads.example.co.uk', {'co.uk'}))
        self.assertFalse(covered_by_parent('example.com', {'example.com'}))


if __name__ == '__main__':
    unittest.main()

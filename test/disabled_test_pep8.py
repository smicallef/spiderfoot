# https://pep8.readthedocs.io/en/latest/advanced.html
import os
import unittest
import pycodestyle

class TestPep8(unittest.TestCase):
    """Run PEP8 on all files in this directory and subdirectories."""
    def test_pep8(self):
        style = pycodestyle.StyleGuide(quiet=False)
        style.options.max_line_length = 200
        #style.options.ignore += ('W',)

        filenames = []
        for root, _, files in os.walk('.'):
            python_files = [f for f in files if f.endswith('.py')]
            for file in python_files:
                filename = '{0}/{1}'.format(root, file)
                filenames.append(filename)

        check = style.check_files(filenames)
        self.assertEqual(check.total_errors, 0, 'Found %d code style errors and warnings' % check.total_errors)

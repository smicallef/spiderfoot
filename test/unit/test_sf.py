# test_sf.py
import unittest
import io
import sys
import subprocess

class TestSf(unittest.TestCase):
    """
    Test TestSf
    """

    def execute(self, command):
        proc = subprocess.Popen(
           command,
           stdout = subprocess.PIPE,
           stderr = subprocess.PIPE,
        )
        out,err = proc.communicate()
        return out, err, proc.returncode

    def test_help_arg_should_print_help_and_exit(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-h"])
        self.assertIn(b"show this help message and exit", out)
        self.assertEqual(b"", err)
        self.assertEqual(0, code)

if __name__ == '__main__':
    unittest.main()


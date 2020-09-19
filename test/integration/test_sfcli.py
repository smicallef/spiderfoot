# test_sfcli.py
import subprocess
import sys
import unittest


class TestSfcli(unittest.TestCase):
    """
    Test TestSfcli
    """

    def execute(self, command):
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out, err = proc.communicate()
        return out, err, proc.returncode

    def test_help_arg_should_print_help_and_exit(self):
        out, err, code = self.execute([sys.executable, "sfcli.py", "-h"])
        self.assertIn(b"show this help message and exit", out)
        self.assertEqual(b"", err)
        self.assertEqual(0, code)

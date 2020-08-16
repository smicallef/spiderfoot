# test_sf.py
import unittest
import io
import sys
import subprocess

class TestSf(unittest.TestCase):
    """
    Test TestSf
    """

    default_types = [
      ""
    ]

    default_modules = [
      "sfp_binstring",
      "sfp_company",
      "sfp_cookie",
      "sfp_countryname",
      "sfp_creditcard",
      "sfp_email",
      "sfp_errors",
      "sfp_ethereum",
      "sfp_filemeta",
      "sfp_hashes",
      "sfp_iban",
      "sfp_names",
      "sfp_pageinfo",
      "sfp_phone",
      "sfp_webanalytics"
    ]

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

    def test_modules_arg_should_print_modules_and_exit(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-M"])
        self.assertIn(b"Modules available:", out)
        self.assertEqual(b"", err)
        self.assertEqual(0, code)

    def test_types_arg_should_print_types_and_exit(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-T"])
        self.assertIn(b"Types available:", out)
        self.assertEqual(b"", err)
        self.assertEqual(0, code)

    def test_run_scan_with_modules_no_target_should_exit(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-m", ",".join(self.default_modules)])
        self.assertIn(b"You must specify a target when running in scan mode", out)
        self.assertEqual(b"", err)
        self.assertEqual(255, code)

    def test_run_scan_with_types_no_target_should_exit(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-t", ",".join(self.default_types)])
        self.assertIn(b"You must specify a target when running in scan mode", out)
        self.assertEqual(b"", err)
        self.assertEqual(255, code)

    def test_run_scan_with_invalid_module_should_run_scan_and_exit(self):
        module = "invalid module"
        out, err, code = self.execute([sys.executable, "sf.py", "-m", module, "-s", "spiderfoot.net"])
        self.assertIn(b"Failed to load module:", out)
        self.assertEqual(b"", err)
        self.assertEqual(0, code)

    def test_run_scan_with_invalid_type_should_exit(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-t", "invalid type", "-s", "spiderfoot.net"])
        self.assertIn(b"Based on your criteria, no modules were enabled", out)
        self.assertEqual(b"", err)
        self.assertEqual(255, code)

    def test_run_scan_with_modules_should_run_scan_and_exit(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-m", ",".join(self.default_modules), "-s", "spiderfoot.net"])
        self.assertIn(b"Scan completed with status FINISHED", out)
        self.assertEqual(b"", err)
        self.assertEqual(0, code)

        for module in self.default_modules:
            with self.subTest(module=module):
                self.assertIn(module.encode(), out)

if __name__ == '__main__':
    unittest.main()


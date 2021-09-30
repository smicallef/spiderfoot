# test_sf.py
import subprocess
import sys
import unittest


class TestSf(unittest.TestCase):
    """
    Test TestSf
    """

    default_types = [
        ""
    ]

    default_modules = [
        "sfp_base64",
        "sfp_bitcoin",
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
        "sfp_strangeheaders",
        "sfp_webframework",
        "sfp_webserver",
        "sfp_webanalytics",
    ]

    def execute(self, command):
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out, err = proc.communicate()
        return out, err, proc.returncode

    def test_no_args_should_print_arg_l_required(self):
        out, err, code = self.execute([sys.executable, "sf.py"])
        self.assertIn(b"SpiderFoot requires -l <ip>:<port> to start the web server. Try --help for guidance.", out)
        self.assertEqual(b"", err)
        self.assertEqual(255, code)

    def test_help_arg_should_print_help_and_exit(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-h"])
        self.assertIn(b"show this help message and exit", out)
        self.assertEqual(b"", err)
        self.assertEqual(0, code)

    def test_modules_arg_should_print_modules_and_exit(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-M"])
        self.assertIn(b"Modules available:", err)
        self.assertEqual(0, code)

    def test_types_arg_should_print_types_and_exit(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-T"])
        self.assertIn(b"Types available:", err)
        self.assertEqual(0, code)

    @unittest.skip("todo")
    def test_l_arg_should_start_web_server(self):
        listen = "127.0.0.1:5001"
        out, err, code = self.execute([sys.executable, "sf.py", "-l", listen])
        self.assertIn(bytes(f"Starting web server at {listen}", 'utf-8'), err)
        self.assertEqual(0, code)

    def test_debug_arg_should_enable_and_print_debug_output(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-d", "-m", "example module", "-s", "spiderfoot.net"])
        self.assertIn(b"[DEBUG]", err)
        self.assertIn(b"sfp__stor_db : Storing an event: ROOT", err)
        self.assertEqual(0, code)

    def test_quiet_arg_should_hide_debug_output(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-q", "-m", "example module", "-s", "spiderfoot.net"])
        self.assertNotIn(b"[INFO]", err)
        self.assertEqual(0, code)

    def test_run_scan_invalid_target_should_exit(self):
        invalid_target = '.'
        out, err, code = self.execute([sys.executable, "sf.py", "-s", invalid_target])
        self.assertIn(bytes(f"Could not determine target type. Invalid target: {invalid_target}", 'utf-8'), err)
        self.assertEqual(255, code)

    def test_run_scan_with_modules_no_target_should_exit(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-m", ",".join(self.default_modules)])
        self.assertIn(b"You must specify a target when running in scan mode", err)
        self.assertEqual(255, code)

    def test_run_scan_with_types_no_target_should_exit(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-t", ",".join(self.default_types)])
        self.assertIn(b"You must specify a target when running in scan mode", err)
        self.assertEqual(255, code)

    def test_run_scan_with_invalid_module_should_run_scan_and_exit(self):
        module = "invalid module"
        out, err, code = self.execute([sys.executable, "sf.py", "-m", module, "-s", "spiderfoot.net"])
        self.assertIn(bytes(f"Failed to load module: {module}", 'utf-8'), err)
        self.assertEqual(0, code)

    def test_run_scan_with_invalid_type_should_exit(self):
        out, err, code = self.execute([sys.executable, "sf.py", "-t", "invalid type", "-s", "spiderfoot.net"])
        self.assertIn(b"Based on your criteria, no modules were enabled", err)
        self.assertEqual(255, code)

    def test_run_scan_should_run_scan_and_exit(self):
        target = "spiderfoot.net"
        out, err, code = self.execute([sys.executable, "sf.py", "-m", ",".join(self.default_modules), "-s", target])
        self.assertIn(b"Scan completed with status FINISHED", err)
        self.assertEqual(0, code)

        for module in self.default_modules:
            with self.subTest(module=module):
                self.assertIn(module.encode(), err)

    @unittest.skip("output buffering sometimes causes this test to fail")
    def test_run_scan_should_print_scan_result_and_exit(self):
        target = "spiderfoot.net"
        out, err, code = self.execute([sys.executable, "sf.py", "-m", ",".join(self.default_modules), "-s", target, "-o", "csv"])
        self.assertIn(b"Scan completed with status FINISHED", err)
        self.assertEqual(0, code)

        for module in self.default_modules:
            with self.subTest(module=module):
                self.assertIn(module.encode(), err)

        expected_output = [
            "Source,Type,Data",
            "SpiderFoot UI,Internet Name,spiderfoot.net,spiderfoot.net\n",
            "SpiderFoot UI,Domain Name,spiderfoot.net,spiderfoot.net\n",
            "sfp_countryname,Country Name,spiderfoot.net,United States\n",
        ]
        for output in expected_output:
            self.assertIn(bytes(output, 'utf-8'), out)

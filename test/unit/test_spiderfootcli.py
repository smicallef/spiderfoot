# test_spiderfootcli.py
from sfcli import SpiderFootCli
import unittest
import subprocess

class TestSpiderFootCli(unittest.TestCase):
    """
    Test TestSpiderFootCli
    """

    def execute(self, command):
        proc = subprocess.Popen(
           command,
           stdout = subprocess.PIPE,
           stderr = subprocess.PIPE,
        )
        out,err = proc.communicate()
        return out, err, proc.returncode

    def test_help_arg_should_print_help(self):
        out, err, code = self.execute(["python3", "sfcli.py", "-h"])
        self.assertIn(b"show this help message and exit", out)
        self.assertEqual(b"", err)
        self.assertEqual(0, code)

    def test_no_args(self):
        out, err, code = self.execute(["python3", "sfcli.py"])
        self.assertEqual(b"", err)
        self.assertEqual(0, code)

    @unittest.skip("todo")
    def test_default(self):
        """
        Test default(self, line)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_complete_start(self):
        """
        Test complete_start(self, text, line, startidx, endidx)
        """
        sfcli = SpiderFootCli()
        sfcli.complete_start(None, None, None, None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_complete_find(self):
        """
        Test complete_find(self, text, line, startidx, endidx)
        """
        sfcli = SpiderFootCli()
        sfcli.complete_find(None, None, None, None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_complete_data(self):
        """
        Test complete_data(self, text, line, startidx, endidx)
        """
        sfcli = SpiderFootCli()
        sfcli.complete_data(None, None, None, None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_complete_default(self):
        """
        Test complete_default(self, text, line, startidx, endidx)
        """
        sfcli = SpiderFootCli()
        sfcli.complete_default(None, None, None, None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_dprint(self):
        """
        Test dprint(self, msg, err=False, deb=False, plain=False, color=None)
        """
        sfcli = SpiderFootCli()
        sfcli.dprint(None, None, None, None, None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_debug(self):
        """
        Test do_debug(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_debug(None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_spool(self):
        """
        Test do_spool(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_spool(None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_history(self):
        """
        Test do_history(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_history(None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_precmd(self):
        """
        Test precmd(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.precmd(None)

        self.assertEqual('TBD', 'TBD')

    def test_ddprint(self):
        """
        Test ddprint(self, msg)
        """
        sfcli = SpiderFootCli()
        sfcli.ddprint(None)

    @unittest.skip("todo")
    def test_edprint(self):
        """
        Test edprint(self, msg)
        """
        sfcli = SpiderFootCli()
        sfcli.edprint(None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_pretty(self):
        """
        Test pretty(self, data, titlemap=None)
        """
        sfcli = SpiderFootCli()
        sfcli.pretty(None, None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_request(self):
        """
        Test request(self, url, post=None)
        """
        sfcli = SpiderFootCli()
        sfcli.request(None, None)

        self.assertEqual('TBD', 'TBD')

    def test_emptyline_should_return_none(self):
        """
        Test emptyline(self)
        """
        sfcli = SpiderFootCli()
        emptyline = sfcli.emptyline()
        self.assertEqual(None, emptyline)

    def test_completedefault_should_return_empty_list(self):
        """
        Test completedefault(self, text, line, begidx, endidx)
        """
        sfcli = SpiderFootCli()
        completedefault = sfcli.completedefault(None, None, None, None)
        self.assertIsInstance(completedefault, list)
        self.assertEqual([], completedefault)

    @unittest.skip("todo")
    def test_myparseline(self):
        """
        Test myparseline(self, cmdline, replace=True)
        """
        sfcli = SpiderFootCli()
        sfcli.myparseline(None, None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_send_output(self):
        """
        Test send_output(self, data, cmd, titles=None, total=True, raw=False)
        """
        sfcli = SpiderFootCli()
        sfcli.send_output(None, None, None, None, None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_query(self):
        """
        Test do_query(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_query(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_ping(self):
        """
        Test do_ping(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_ping(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_modules(self):
        """
        Test do_modules(self, line, cacheonly=False)
        """
        sfcli = SpiderFootCli()
        sfcli.do_modules(None, None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_types(self):
        """
        Test do_types(self, line, cacheonly=False)
        """
        sfcli = SpiderFootCli()
        sfcli.do_types(None, None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_load(self):
        """
        Test do_load(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_load(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_scaninfo(self):
        """
        Test do_scaninfo(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_scaninfo(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_scans(self):
        """
        Test do_scans(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_scans(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_data(self):
        """
        Test do_data(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_data(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_export(self):
        """
        Test do_export(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_export(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_logs(self):
        """
        Test do_logs(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_logs(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_start(self):
        """
        Test do_start(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_start(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_stop(self):
        """
        Test do_stop(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_stop(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_search(self):
        """
        Test do_search(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_search(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_find(self):
        """
        Test do_find(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_find(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_summary(self):
        """
        Test do_summary(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_summary(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_delete(self):
        """
        Test do_delete(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_delete(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_print_topic(self):
        """
        Test print_topics(self, header, cmds, cmdlen, maxcol)
        """
        sfcli = SpiderFootCli()
        sfcli.print_topics(None, None, None, None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_set(self):
        """
        Test do_set(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_set(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_shell(self):
        """
        Test do_shell(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_shell(None)
 
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_do_clear(self):
        """
        Test do_clear(self, line)
        """
        sfcli = SpiderFootCli()
        sfcli.do_clear(None)
 
        self.assertEqual('TBD', 'TBD')

    def test_do_exit(self):
        """
        Test do_exit(self, line)
        """
        sfcli = SpiderFootCli()
        do_exit = sfcli.do_exit(None)
        self.assertTrue(do_exit)

    def test_do_eof(self):
        """
        Test do_EOF(self, line)
        """
        sfcli = SpiderFootCli()
        do_eof = sfcli.do_EOF(None)
        self.assertTrue(do_eof)

if __name__ == '__main__':
    unittest.main()


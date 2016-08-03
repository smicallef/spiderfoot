"""Tests to ensure that the html.parser tree builder generates good
trees."""

from pdb import set_trace
import pickle
from bs4.testing import SoupTest, HTMLTreeBuilderSmokeTest
from bs4.builder import HTMLParserTreeBuilder

class HTMLParserTreeBuilderSmokeTest(SoupTest, HTMLTreeBuilderSmokeTest):

    @property
    def default_builder(self):
        return HTMLParserTreeBuilder()

    def test_namespaced_system_doctype(self):
        # html.parser can't handle namespaced doctypes, so skip this one.
        pass

    def test_namespaced_public_doctype(self):
        # html.parser can't handle namespaced doctypes, so skip this one.
        pass

    def test_builder_is_pickled(self):
        """Unlike most tree builders, HTMLParserTreeBuilder and will
        be restored after pickling.
        """
        tree = self.soup("<a><b>foo</a>")
        dumped = pickle.dumps(tree, 2)
        loaded = pickle.loads(dumped)
        self.assertTrue(isinstance(loaded.builder, type(tree.builder)))



# -*- coding: utf-8 -*-
"""Tests for Beautiful Soup's tree traversal methods.

The tree traversal methods are the main advantage of using Beautiful
Soup over just using a parser.

Different parsers will build different Beautiful Soup trees given the
same markup, but all Beautiful Soup trees can be traversed with the
methods tested here.
"""

from pdb import set_trace
import copy
import pickle
import re
import warnings
from bs4 import BeautifulSoup
from bs4.builder import (
    builder_registry,
    HTMLParserTreeBuilder,
)
from bs4.element import (
    PY3K,
    CData,
    Comment,
    Declaration,
    Doctype,
    NavigableString,
    SoupStrainer,
    Tag,
)
from bs4.testing import (
    SoupTest,
    skipIf,
)

XML_BUILDER_PRESENT = (builder_registry.lookup("xml") is not None)
LXML_PRESENT = (builder_registry.lookup("lxml") is not None)

class TreeTest(SoupTest):

    def assertSelects(self, tags, should_match):
        """Make sure that the given tags have the correct text.

        This is used in tests that define a bunch of tags, each
        containing a single string, and then select certain strings by
        some mechanism.
        """
        self.assertEqual([tag.string for tag in tags], should_match)

    def assertSelectsIDs(self, tags, should_match):
        """Make sure that the given tags have the correct IDs.

        This is used in tests that define a bunch of tags, each
        containing a single string, and then select certain strings by
        some mechanism.
        """
        self.assertEqual([tag['id'] for tag in tags], should_match)


class TestFind(TreeTest):
    """Basic tests of the find() method.

    find() just calls find_all() with limit=1, so it's not tested all
    that thouroughly here.
    """

    def test_find_tag(self):
        soup = self.soup("<a>1</a><b>2</b><a>3</a><b>4</b>")
        self.assertEqual(soup.find("b").string, "2")

    def test_unicode_text_find(self):
        soup = self.soup(u'<h1>Räksmörgås</h1>')
        self.assertEqual(soup.find(string=u'Räksmörgås'), u'Räksmörgås')

    def test_unicode_attribute_find(self):
        soup = self.soup(u'<h1 id="Räksmörgås">here it is</h1>')
        str(soup)
        self.assertEqual("here it is", soup.find(id=u'Räksmörgås').text)


    def test_find_everything(self):
        """Test an optimization that finds all tags."""
        soup = self.soup("<a>foo</a><b>bar</b>")
        self.assertEqual(2, len(soup.find_all()))

    def test_find_everything_with_name(self):
        """Test an optimization that finds all tags with a given name."""
        soup = self.soup("<a>foo</a><b>bar</b><a>baz</a>")
        self.assertEqual(2, len(soup.find_all('a')))

class TestFindAll(TreeTest):
    """Basic tests of the find_all() method."""

    def test_find_all_text_nodes(self):
        """You can search the tree for text nodes."""
        soup = self.soup("<html>Foo<b>bar</b>\xbb</html>")
        # Exact match.
        self.assertEqual(soup.find_all(string="bar"), [u"bar"])
        self.assertEqual(soup.find_all(text="bar"), [u"bar"])
        # Match any of a number of strings.
        self.assertEqual(
            soup.find_all(text=["Foo", "bar"]), [u"Foo", u"bar"])
        # Match a regular expression.
        self.assertEqual(soup.find_all(text=re.compile('.*')),
                         [u"Foo", u"bar", u'\xbb'])
        # Match anything.
        self.assertEqual(soup.find_all(text=True),
                         [u"Foo", u"bar", u'\xbb'])

    def test_find_all_limit(self):
        """You can limit the number of items returned by find_all."""
        soup = self.soup("<a>1</a><a>2</a><a>3</a><a>4</a><a>5</a>")
        self.assertSelects(soup.find_all('a', limit=3), ["1", "2", "3"])
        self.assertSelects(soup.find_all('a', limit=1), ["1"])
        self.assertSelects(
            soup.find_all('a', limit=10), ["1", "2", "3", "4", "5"])

        # A limit of 0 means no limit.
        self.assertSelects(
            soup.find_all('a', limit=0), ["1", "2", "3", "4", "5"])

    def test_calling_a_tag_is_calling_findall(self):
        soup = self.soup("<a>1</a><b>2<a id='foo'>3</a></b>")
        self.assertSelects(soup('a', limit=1), ["1"])
        self.assertSelects(soup.b(id="foo"), ["3"])

    def test_find_all_with_self_referential_data_structure_does_not_cause_infinite_recursion(self):
        soup = self.soup("<a></a>")
        # Create a self-referential list.
        l = []
        l.append(l)

        # Without special code in _normalize_search_value, this would cause infinite
        # recursion.
        self.assertEqual([], soup.find_all(l))

    def test_find_all_resultset(self):
        """All find_all calls return a ResultSet"""
        soup = self.soup("<a></a>")
        result = soup.find_all("a")
        self.assertTrue(hasattr(result, "source"))

        result = soup.find_all(True)
        self.assertTrue(hasattr(result, "source"))

        result = soup.find_all(text="foo")
        self.assertTrue(hasattr(result, "source"))


class TestFindAllBasicNamespaces(TreeTest):

    def test_find_by_namespaced_name(self):
        soup = self.soup('<mathml:msqrt>4</mathml:msqrt><a svg:fill="red">')
        self.assertEqual("4", soup.find("mathml:msqrt").string)
        self.assertEqual("a", soup.find(attrs= { "svg:fill" : "red" }).name)


class TestFindAllByName(TreeTest):
    """Test ways of finding tags by tag name."""

    def setUp(self):
        super(TreeTest, self).setUp()
        self.tree =  self.soup("""<a>First tag.</a>
                                  <b>Second tag.</b>
                                  <c>Third <a>Nested tag.</a> tag.</c>""")

    def test_find_all_by_tag_name(self):
        # Find all the <a> tags.
        self.assertSelects(
            self.tree.find_all('a'), ['First tag.', 'Nested tag.'])

    def test_find_all_by_name_and_text(self):
        self.assertSelects(
            self.tree.find_all('a', text='First tag.'), ['First tag.'])

        self.assertSelects(
            self.tree.find_all('a', text=True), ['First tag.', 'Nested tag.'])

        self.assertSelects(
            self.tree.find_all('a', text=re.compile("tag")),
            ['First tag.', 'Nested tag.'])


    def test_find_all_on_non_root_element(self):
        # You can call find_all on any node, not just the root.
        self.assertSelects(self.tree.c.find_all('a'), ['Nested tag.'])

    def test_calling_element_invokes_find_all(self):
        self.assertSelects(self.tree('a'), ['First tag.', 'Nested tag.'])

    def test_find_all_by_tag_strainer(self):
        self.assertSelects(
            self.tree.find_all(SoupStrainer('a')),
            ['First tag.', 'Nested tag.'])

    def test_find_all_by_tag_names(self):
        self.assertSelects(
            self.tree.find_all(['a', 'b']),
            ['First tag.', 'Second tag.', 'Nested tag.'])

    def test_find_all_by_tag_dict(self):
        self.assertSelects(
            self.tree.find_all({'a' : True, 'b' : True}),
            ['First tag.', 'Second tag.', 'Nested tag.'])

    def test_find_all_by_tag_re(self):
        self.assertSelects(
            self.tree.find_all(re.compile('^[ab]$')),
            ['First tag.', 'Second tag.', 'Nested tag.'])

    def test_find_all_with_tags_matching_method(self):
        # You can define an oracle method that determines whether
        # a tag matches the search.
        def id_matches_name(tag):
            return tag.name == tag.get('id')

        tree = self.soup("""<a id="a">Match 1.</a>
                            <a id="1">Does not match.</a>
                            <b id="b">Match 2.</a>""")

        self.assertSelects(
            tree.find_all(id_matches_name), ["Match 1.", "Match 2."])


class TestFindAllByAttribute(TreeTest):

    def test_find_all_by_attribute_name(self):
        # You can pass in keyword arguments to find_all to search by
        # attribute.
        tree = self.soup("""
                         <a id="first">Matching a.</a>
                         <a id="second">
                          Non-matching <b id="first">Matching b.</b>a.
                         </a>""")
        self.assertSelects(tree.find_all(id='first'),
                           ["Matching a.", "Matching b."])

    def test_find_all_by_utf8_attribute_value(self):
        peace = u"םולש".encode("utf8")
        data = u'<a title="םולש"></a>'.encode("utf8")
        soup = self.soup(data)
        self.assertEqual([soup.a], soup.find_all(title=peace))
        self.assertEqual([soup.a], soup.find_all(title=peace.decode("utf8")))
        self.assertEqual([soup.a], soup.find_all(title=[peace, "something else"]))

    def test_find_all_by_attribute_dict(self):
        # You can pass in a dictionary as the argument 'attrs'. This
        # lets you search for attributes like 'name' (a fixed argument
        # to find_all) and 'class' (a reserved word in Python.)
        tree = self.soup("""
                         <a name="name1" class="class1">Name match.</a>
                         <a name="name2" class="class2">Class match.</a>
                         <a name="name3" class="class3">Non-match.</a>
                         <name1>A tag called 'name1'.</name1>
                         """)

        # This doesn't do what you want.
        self.assertSelects(tree.find_all(name='name1'),
                           ["A tag called 'name1'."])
        # This does what you want.
        self.assertSelects(tree.find_all(attrs={'name' : 'name1'}),
                           ["Name match."])

        self.assertSelects(tree.find_all(attrs={'class' : 'class2'}),
                           ["Class match."])

    def test_find_all_by_class(self):
        tree = self.soup("""
                         <a class="1">Class 1.</a>
                         <a class="2">Class 2.</a>
                         <b class="1">Class 1.</b>
                         <c class="3 4">Class 3 and 4.</c>
                         """)

        # Passing in the class_ keyword argument will search against
        # the 'class' attribute.
        self.assertSelects(tree.find_all('a', class_='1'), ['Class 1.'])
        self.assertSelects(tree.find_all('c', class_='3'), ['Class 3 and 4.'])
        self.assertSelects(tree.find_all('c', class_='4'), ['Class 3 and 4.'])

        # Passing in a string to 'attrs' will also search the CSS class.
        self.assertSelects(tree.find_all('a', '1'), ['Class 1.'])
        self.assertSelects(tree.find_all(attrs='1'), ['Class 1.', 'Class 1.'])
        self.assertSelects(tree.find_all('c', '3'), ['Class 3 and 4.'])
        self.assertSelects(tree.find_all('c', '4'), ['Class 3 and 4.'])

    def test_find_by_class_when_multiple_classes_present(self):
        tree = self.soup("<gar class='foo bar'>Found it</gar>")

        f = tree.find_all("gar", class_=re.compile("o"))
        self.assertSelects(f, ["Found it"])

        f = tree.find_all("gar", class_=re.compile("a"))
        self.assertSelects(f, ["Found it"])

        # Since the class is not the string "foo bar", but the two
        # strings "foo" and "bar", this will not find anything.
        f = tree.find_all("gar", class_=re.compile("o b"))
        self.assertSelects(f, [])

    def test_find_all_with_non_dictionary_for_attrs_finds_by_class(self):
        soup = self.soup("<a class='bar'>Found it</a>")

        self.assertSelects(soup.find_all("a", re.compile("ba")), ["Found it"])

        def big_attribute_value(value):
            return len(value) > 3

        self.assertSelects(soup.find_all("a", big_attribute_value), [])

        def small_attribute_value(value):
            return len(value) <= 3

        self.assertSelects(
            soup.find_all("a", small_attribute_value), ["Found it"])

    def test_find_all_with_string_for_attrs_finds_multiple_classes(self):
        soup = self.soup('<a class="foo bar"></a><a class="foo"></a>')
        a, a2 = soup.find_all("a")
        self.assertEqual([a, a2], soup.find_all("a", "foo"))
        self.assertEqual([a], soup.find_all("a", "bar"))

        # If you specify the class as a string that contains a
        # space, only that specific value will be found.
        self.assertEqual([a], soup.find_all("a", class_="foo bar"))
        self.assertEqual([a], soup.find_all("a", "foo bar"))
        self.assertEqual([], soup.find_all("a", "bar foo"))

    def test_find_all_by_attribute_soupstrainer(self):
        tree = self.soup("""
                         <a id="first">Match.</a>
                         <a id="second">Non-match.</a>""")

        strainer = SoupStrainer(attrs={'id' : 'first'})
        self.assertSelects(tree.find_all(strainer), ['Match.'])

    def test_find_all_with_missing_atribute(self):
        # You can pass in None as the value of an attribute to find_all.
        # This will match tags that do not have that attribute set.
        tree = self.soup("""<a id="1">ID present.</a>
                            <a>No ID present.</a>
                            <a id="">ID is empty.</a>""")
        self.assertSelects(tree.find_all('a', id=None), ["No ID present."])

    def test_find_all_with_defined_attribute(self):
        # You can pass in None as the value of an attribute to find_all.
        # This will match tags that have that attribute set to any value.
        tree = self.soup("""<a id="1">ID present.</a>
                            <a>No ID present.</a>
                            <a id="">ID is empty.</a>""")
        self.assertSelects(
            tree.find_all(id=True), ["ID present.", "ID is empty."])

    def test_find_all_with_numeric_attribute(self):
        # If you search for a number, it's treated as a string.
        tree = self.soup("""<a id=1>Unquoted attribute.</a>
                            <a id="1">Quoted attribute.</a>""")

        expected = ["Unquoted attribute.", "Quoted attribute."]
        self.assertSelects(tree.find_all(id=1), expected)
        self.assertSelects(tree.find_all(id="1"), expected)

    def test_find_all_with_list_attribute_values(self):
        # You can pass a list of attribute values instead of just one,
        # and you'll get tags that match any of the values.
        tree = self.soup("""<a id="1">1</a>
                            <a id="2">2</a>
                            <a id="3">3</a>
                            <a>No ID.</a>""")
        self.assertSelects(tree.find_all(id=["1", "3", "4"]),
                           ["1", "3"])

    def test_find_all_with_regular_expression_attribute_value(self):
        # You can pass a regular expression as an attribute value, and
        # you'll get tags whose values for that attribute match the
        # regular expression.
        tree = self.soup("""<a id="a">One a.</a>
                            <a id="aa">Two as.</a>
                            <a id="ab">Mixed as and bs.</a>
                            <a id="b">One b.</a>
                            <a>No ID.</a>""")

        self.assertSelects(tree.find_all(id=re.compile("^a+$")),
                           ["One a.", "Two as."])

    def test_find_by_name_and_containing_string(self):
        soup = self.soup("<b>foo</b><b>bar</b><a>foo</a>")
        a = soup.a

        self.assertEqual([a], soup.find_all("a", text="foo"))
        self.assertEqual([], soup.find_all("a", text="bar"))
        self.assertEqual([], soup.find_all("a", text="bar"))

    def test_find_by_name_and_containing_string_when_string_is_buried(self):
        soup = self.soup("<a>foo</a><a><b><c>foo</c></b></a>")
        self.assertEqual(soup.find_all("a"), soup.find_all("a", text="foo"))

    def test_find_by_attribute_and_containing_string(self):
        soup = self.soup('<b id="1">foo</b><a id="2">foo</a>')
        a = soup.a

        self.assertEqual([a], soup.find_all(id=2, text="foo"))
        self.assertEqual([], soup.find_all(id=1, text="bar"))




class TestIndex(TreeTest):
    """Test Tag.index"""
    def test_index(self):
        tree = self.soup("""<div>
                            <a>Identical</a>
                            <b>Not identical</b>
                            <a>Identical</a>

                            <c><d>Identical with child</d></c>
                            <b>Also not identical</b>
                            <c><d>Identical with child</d></c>
                            </div>""")
        div = tree.div
        for i, element in enumerate(div.contents):
            self.assertEqual(i, div.index(element))
        self.assertRaises(ValueError, tree.index, 1)


class TestParentOperations(TreeTest):
    """Test navigation and searching through an element's parents."""

    def setUp(self):
        super(TestParentOperations, self).setUp()
        self.tree = self.soup('''<ul id="empty"></ul>
                                 <ul id="top">
                                  <ul id="middle">
                                   <ul id="bottom">
                                    <b>Start here</b>
                                   </ul>
                                  </ul>''')
        self.start = self.tree.b


    def test_parent(self):
        self.assertEqual(self.start.parent['id'], 'bottom')
        self.assertEqual(self.start.parent.parent['id'], 'middle')
        self.assertEqual(self.start.parent.parent.parent['id'], 'top')

    def test_parent_of_top_tag_is_soup_object(self):
        top_tag = self.tree.contents[0]
        self.assertEqual(top_tag.parent, self.tree)

    def test_soup_object_has_no_parent(self):
        self.assertEqual(None, self.tree.parent)

    def test_find_parents(self):
        self.assertSelectsIDs(
            self.start.find_parents('ul'), ['bottom', 'middle', 'top'])
        self.assertSelectsIDs(
            self.start.find_parents('ul', id="middle"), ['middle'])

    def test_find_parent(self):
        self.assertEqual(self.start.find_parent('ul')['id'], 'bottom')
        self.assertEqual(self.start.find_parent('ul', id='top')['id'], 'top')

    def test_parent_of_text_element(self):
        text = self.tree.find(text="Start here")
        self.assertEqual(text.parent.name, 'b')

    def test_text_element_find_parent(self):
        text = self.tree.find(text="Start here")
        self.assertEqual(text.find_parent('ul')['id'], 'bottom')

    def test_parent_generator(self):
        parents = [parent['id'] for parent in self.start.parents
                   if parent is not None and 'id' in parent.attrs]
        self.assertEqual(parents, ['bottom', 'middle', 'top'])


class ProximityTest(TreeTest):

    def setUp(self):
        super(TreeTest, self).setUp()
        self.tree = self.soup(
            '<html id="start"><head></head><body><b id="1">One</b><b id="2">Two</b><b id="3">Three</b></body></html>')


class TestNextOperations(ProximityTest):

    def setUp(self):
        super(TestNextOperations, self).setUp()
        self.start = self.tree.b

    def test_next(self):
        self.assertEqual(self.start.next_element, "One")
        self.assertEqual(self.start.next_element.next_element['id'], "2")

    def test_next_of_last_item_is_none(self):
        last = self.tree.find(text="Three")
        self.assertEqual(last.next_element, None)

    def test_next_of_root_is_none(self):
        # The document root is outside the next/previous chain.
        self.assertEqual(self.tree.next_element, None)

    def test_find_all_next(self):
        self.assertSelects(self.start.find_all_next('b'), ["Two", "Three"])
        self.start.find_all_next(id=3)
        self.assertSelects(self.start.find_all_next(id=3), ["Three"])

    def test_find_next(self):
        self.assertEqual(self.start.find_next('b')['id'], '2')
        self.assertEqual(self.start.find_next(text="Three"), "Three")

    def test_find_next_for_text_element(self):
        text = self.tree.find(text="One")
        self.assertEqual(text.find_next("b").string, "Two")
        self.assertSelects(text.find_all_next("b"), ["Two", "Three"])

    def test_next_generator(self):
        start = self.tree.find(text="Two")
        successors = [node for node in start.next_elements]
        # There are two successors: the final <b> tag and its text contents.
        tag, contents = successors
        self.assertEqual(tag['id'], '3')
        self.assertEqual(contents, "Three")

class TestPreviousOperations(ProximityTest):

    def setUp(self):
        super(TestPreviousOperations, self).setUp()
        self.end = self.tree.find(text="Three")

    def test_previous(self):
        self.assertEqual(self.end.previous_element['id'], "3")
        self.assertEqual(self.end.previous_element.previous_element, "Two")

    def test_previous_of_first_item_is_none(self):
        first = self.tree.find('html')
        self.assertEqual(first.previous_element, None)

    def test_previous_of_root_is_none(self):
        # The document root is outside the next/previous chain.
        # XXX This is broken!
        #self.assertEqual(self.tree.previous_element, None)
        pass

    def test_find_all_previous(self):
        # The <b> tag containing the "Three" node is the predecessor
        # of the "Three" node itself, which is why "Three" shows up
        # here.
        self.assertSelects(
            self.end.find_all_previous('b'), ["Three", "Two", "One"])
        self.assertSelects(self.end.find_all_previous(id=1), ["One"])

    def test_find_previous(self):
        self.assertEqual(self.end.find_previous('b')['id'], '3')
        self.assertEqual(self.end.find_previous(text="One"), "One")

    def test_find_previous_for_text_element(self):
        text = self.tree.find(text="Three")
        self.assertEqual(text.find_previous("b").string, "Three")
        self.assertSelects(
            text.find_all_previous("b"), ["Three", "Two", "One"])

    def test_previous_generator(self):
        start = self.tree.find(text="One")
        predecessors = [node for node in start.previous_elements]

        # There are four predecessors: the <b> tag containing "One"
        # the <body> tag, the <head> tag, and the <html> tag.
        b, body, head, html = predecessors
        self.assertEqual(b['id'], '1')
        self.assertEqual(body.name, "body")
        self.assertEqual(head.name, "head")
        self.assertEqual(html.name, "html")


class SiblingTest(TreeTest):

    def setUp(self):
        super(SiblingTest, self).setUp()
        markup = '''<html>
                    <span id="1">
                     <span id="1.1"></span>
                    </span>
                    <span id="2">
                     <span id="2.1"></span>
                    </span>
                    <span id="3">
                     <span id="3.1"></span>
                    </span>
                    <span id="4"></span>
                    </html>'''
        # All that whitespace looks good but makes the tests more
        # difficult. Get rid of it.
        markup = re.compile("\n\s*").sub("", markup)
        self.tree = self.soup(markup)


class TestNextSibling(SiblingTest):

    def setUp(self):
        super(TestNextSibling, self).setUp()
        self.start = self.tree.find(id="1")

    def test_next_sibling_of_root_is_none(self):
        self.assertEqual(self.tree.next_sibling, None)

    def test_next_sibling(self):
        self.assertEqual(self.start.next_sibling['id'], '2')
        self.assertEqual(self.start.next_sibling.next_sibling['id'], '3')

        # Note the difference between next_sibling and next_element.
        self.assertEqual(self.start.next_element['id'], '1.1')

    def test_next_sibling_may_not_exist(self):
        self.assertEqual(self.tree.html.next_sibling, None)

        nested_span = self.tree.find(id="1.1")
        self.assertEqual(nested_span.next_sibling, None)

        last_span = self.tree.find(id="4")
        self.assertEqual(last_span.next_sibling, None)

    def test_find_next_sibling(self):
        self.assertEqual(self.start.find_next_sibling('span')['id'], '2')

    def test_next_siblings(self):
        self.assertSelectsIDs(self.start.find_next_siblings("span"),
                              ['2', '3', '4'])

        self.assertSelectsIDs(self.start.find_next_siblings(id='3'), ['3'])

    def test_next_sibling_for_text_element(self):
        soup = self.soup("Foo<b>bar</b>baz")
        start = soup.find(text="Foo")
        self.assertEqual(start.next_sibling.name, 'b')
        self.assertEqual(start.next_sibling.next_sibling, 'baz')

        self.assertSelects(start.find_next_siblings('b'), ['bar'])
        self.assertEqual(start.find_next_sibling(text="baz"), "baz")
        self.assertEqual(start.find_next_sibling(text="nonesuch"), None)


class TestPreviousSibling(SiblingTest):

    def setUp(self):
        super(TestPreviousSibling, self).setUp()
        self.end = self.tree.find(id="4")

    def test_previous_sibling_of_root_is_none(self):
        self.assertEqual(self.tree.previous_sibling, None)

    def test_previous_sibling(self):
        self.assertEqual(self.end.previous_sibling['id'], '3')
        self.assertEqual(self.end.previous_sibling.previous_sibling['id'], '2')

        # Note the difference between previous_sibling and previous_element.
        self.assertEqual(self.end.previous_element['id'], '3.1')

    def test_previous_sibling_may_not_exist(self):
        self.assertEqual(self.tree.html.previous_sibling, None)

        nested_span = self.tree.find(id="1.1")
        self.assertEqual(nested_span.previous_sibling, None)

        first_span = self.tree.find(id="1")
        self.assertEqual(first_span.previous_sibling, None)

    def test_find_previous_sibling(self):
        self.assertEqual(self.end.find_previous_sibling('span')['id'], '3')

    def test_previous_siblings(self):
        self.assertSelectsIDs(self.end.find_previous_siblings("span"),
                              ['3', '2', '1'])

        self.assertSelectsIDs(self.end.find_previous_siblings(id='1'), ['1'])

    def test_previous_sibling_for_text_element(self):
        soup = self.soup("Foo<b>bar</b>baz")
        start = soup.find(text="baz")
        self.assertEqual(start.previous_sibling.name, 'b')
        self.assertEqual(start.previous_sibling.previous_sibling, 'Foo')

        self.assertSelects(start.find_previous_siblings('b'), ['bar'])
        self.assertEqual(start.find_previous_sibling(text="Foo"), "Foo")
        self.assertEqual(start.find_previous_sibling(text="nonesuch"), None)


class TestTagCreation(SoupTest):
    """Test the ability to create new tags."""
    def test_new_tag(self):
        soup = self.soup("")
        new_tag = soup.new_tag("foo", bar="baz")
        self.assertTrue(isinstance(new_tag, Tag))
        self.assertEqual("foo", new_tag.name)
        self.assertEqual(dict(bar="baz"), new_tag.attrs)
        self.assertEqual(None, new_tag.parent)

    def test_tag_inherits_self_closing_rules_from_builder(self):
        if XML_BUILDER_PRESENT:
            xml_soup = BeautifulSoup("", "lxml-xml")
            xml_br = xml_soup.new_tag("br")
            xml_p = xml_soup.new_tag("p")

            # Both the <br> and <p> tag are empty-element, just because
            # they have no contents.
            self.assertEqual(b"<br/>", xml_br.encode())
            self.assertEqual(b"<p/>", xml_p.encode())

        html_soup = BeautifulSoup("", "html.parser")
        html_br = html_soup.new_tag("br")
        html_p = html_soup.new_tag("p")

        # The HTML builder users HTML's rules about which tags are
        # empty-element tags, and the new tags reflect these rules.
        self.assertEqual(b"<br/>", html_br.encode())
        self.assertEqual(b"<p></p>", html_p.encode())

    def test_new_string_creates_navigablestring(self):
        soup = self.soup("")
        s = soup.new_string("foo")
        self.assertEqual("foo", s)
        self.assertTrue(isinstance(s, NavigableString))

    def test_new_string_can_create_navigablestring_subclass(self):
        soup = self.soup("")
        s = soup.new_string("foo", Comment)
        self.assertEqual("foo", s)
        self.assertTrue(isinstance(s, Comment))

class TestTreeModification(SoupTest):

    def test_attribute_modification(self):
        soup = self.soup('<a id="1"></a>')
        soup.a['id'] = 2
        self.assertEqual(soup.decode(), self.document_for('<a id="2"></a>'))
        del(soup.a['id'])
        self.assertEqual(soup.decode(), self.document_for('<a></a>'))
        soup.a['id2'] = 'foo'
        self.assertEqual(soup.decode(), self.document_for('<a id2="foo"></a>'))

    def test_new_tag_creation(self):
        builder = builder_registry.lookup('html')()
        soup = self.soup("<body></body>", builder=builder)
        a = Tag(soup, builder, 'a')
        ol = Tag(soup, builder, 'ol')
        a['href'] = 'http://foo.com/'
        soup.body.insert(0, a)
        soup.body.insert(1, ol)
        self.assertEqual(
            soup.body.encode(),
            b'<body><a href="http://foo.com/"></a><ol></ol></body>')

    def test_append_to_contents_moves_tag(self):
        doc = """<p id="1">Don't leave me <b>here</b>.</p>
                <p id="2">Don\'t leave!</p>"""
        soup = self.soup(doc)
        second_para = soup.find(id='2')
        bold = soup.b

        # Move the <b> tag to the end of the second paragraph.
        soup.find(id='2').append(soup.b)

        # The <b> tag is now a child of the second paragraph.
        self.assertEqual(bold.parent, second_para)

        self.assertEqual(
            soup.decode(), self.document_for(
                '<p id="1">Don\'t leave me .</p>\n'
                '<p id="2">Don\'t leave!<b>here</b></p>'))

    def test_replace_with_returns_thing_that_was_replaced(self):
        text = "<a></a><b><c></c></b>"
        soup = self.soup(text)
        a = soup.a
        new_a = a.replace_with(soup.c)
        self.assertEqual(a, new_a)

    def test_unwrap_returns_thing_that_was_replaced(self):
        text = "<a><b></b><c></c></a>"
        soup = self.soup(text)
        a = soup.a
        new_a = a.unwrap()
        self.assertEqual(a, new_a)

    def test_replace_with_and_unwrap_give_useful_exception_when_tag_has_no_parent(self):
        soup = self.soup("<a><b>Foo</b></a><c>Bar</c>")
        a = soup.a
        a.extract()
        self.assertEqual(None, a.parent)
        self.assertRaises(ValueError, a.unwrap)
        self.assertRaises(ValueError, a.replace_with, soup.c)

    def test_replace_tag_with_itself(self):
        text = "<a><b></b><c>Foo<d></d></c></a><a><e></e></a>"
        soup = self.soup(text)
        c = soup.c
        soup.c.replace_with(c)
        self.assertEqual(soup.decode(), self.document_for(text))

    def test_replace_tag_with_its_parent_raises_exception(self):
        text = "<a><b></b></a>"
        soup = self.soup(text)
        self.assertRaises(ValueError, soup.b.replace_with, soup.a)

    def test_insert_tag_into_itself_raises_exception(self):
        text = "<a><b></b></a>"
        soup = self.soup(text)
        self.assertRaises(ValueError, soup.a.insert, 0, soup.a)

    def test_replace_with_maintains_next_element_throughout(self):
        soup = self.soup('<p><a>one</a><b>three</b></p>')
        a = soup.a
        b = a.contents[0]
        # Make it so the <a> tag has two text children.
        a.insert(1, "two")

        # Now replace each one with the empty string.
        left, right = a.contents
        left.replaceWith('')
        right.replaceWith('')

        # The <b> tag is still connected to the tree.
        self.assertEqual("three", soup.b.string)

    def test_replace_final_node(self):
        soup = self.soup("<b>Argh!</b>")
        soup.find(text="Argh!").replace_with("Hooray!")
        new_text = soup.find(text="Hooray!")
        b = soup.b
        self.assertEqual(new_text.previous_element, b)
        self.assertEqual(new_text.parent, b)
        self.assertEqual(new_text.previous_element.next_element, new_text)
        self.assertEqual(new_text.next_element, None)

    def test_consecutive_text_nodes(self):
        # A builder should never create two consecutive text nodes,
        # but if you insert one next to another, Beautiful Soup will
        # handle it correctly.
        soup = self.soup("<a><b>Argh!</b><c></c></a>")
        soup.b.insert(1, "Hooray!")

        self.assertEqual(
            soup.decode(), self.document_for(
                "<a><b>Argh!Hooray!</b><c></c></a>"))

        new_text = soup.find(text="Hooray!")
        self.assertEqual(new_text.previous_element, "Argh!")
        self.assertEqual(new_text.previous_element.next_element, new_text)

        self.assertEqual(new_text.previous_sibling, "Argh!")
        self.assertEqual(new_text.previous_sibling.next_sibling, new_text)

        self.assertEqual(new_text.next_sibling, None)
        self.assertEqual(new_text.next_element, soup.c)

    def test_insert_string(self):
        soup = self.soup("<a></a>")
        soup.a.insert(0, "bar")
        soup.a.insert(0, "foo")
        # The string were added to the tag.
        self.assertEqual(["foo", "bar"], soup.a.contents)
        # And they were converted to NavigableStrings.
        self.assertEqual(soup.a.contents[0].next_element, "bar")

    def test_insert_tag(self):
        builder = self.default_builder
        soup = self.soup(
            "<a><b>Find</b><c>lady!</c><d></d></a>", builder=builder)
        magic_tag = Tag(soup, builder, 'magictag')
        magic_tag.insert(0, "the")
        soup.a.insert(1, magic_tag)

        self.assertEqual(
            soup.decode(), self.document_for(
                "<a><b>Find</b><magictag>the</magictag><c>lady!</c><d></d></a>"))

        # Make sure all the relationships are hooked up correctly.
        b_tag = soup.b
        self.assertEqual(b_tag.next_sibling, magic_tag)
        self.assertEqual(magic_tag.previous_sibling, b_tag)

        find = b_tag.find(text="Find")
        self.assertEqual(find.next_element, magic_tag)
        self.assertEqual(magic_tag.previous_element, find)

        c_tag = soup.c
        self.assertEqual(magic_tag.next_sibling, c_tag)
        self.assertEqual(c_tag.previous_sibling, magic_tag)

        the = magic_tag.find(text="the")
        self.assertEqual(the.parent, magic_tag)
        self.assertEqual(the.next_element, c_tag)
        self.assertEqual(c_tag.previous_element, the)

    def test_append_child_thats_already_at_the_end(self):
        data = "<a><b></b></a>"
        soup = self.soup(data)
        soup.a.append(soup.b)
        self.assertEqual(data, soup.decode())

    def test_move_tag_to_beginning_of_parent(self):
        data = "<a><b></b><c></c><d></d></a>"
        soup = self.soup(data)
        soup.a.insert(0, soup.d)
        self.assertEqual("<a><d></d><b></b><c></c></a>", soup.decode())

    def test_insert_works_on_empty_element_tag(self):
        # This is a little strange, since most HTML parsers don't allow
        # markup like this to come through. But in general, we don't
        # know what the parser would or wouldn't have allowed, so
        # I'm letting this succeed for now.
        soup = self.soup("<br/>")
        soup.br.insert(1, "Contents")
        self.assertEqual(str(soup.br), "<br>Contents</br>")

    def test_insert_before(self):
        soup = self.soup("<a>foo</a><b>bar</b>")
        soup.b.insert_before("BAZ")
        soup.a.insert_before("QUUX")
        self.assertEqual(
            soup.decode(), self.document_for("QUUX<a>foo</a>BAZ<b>bar</b>"))

        soup.a.insert_before(soup.b)
        self.assertEqual(
            soup.decode(), self.document_for("QUUX<b>bar</b><a>foo</a>BAZ"))

    def test_insert_after(self):
        soup = self.soup("<a>foo</a><b>bar</b>")
        soup.b.insert_after("BAZ")
        soup.a.insert_after("QUUX")
        self.assertEqual(
            soup.decode(), self.document_for("<a>foo</a>QUUX<b>bar</b>BAZ"))
        soup.b.insert_after(soup.a)
        self.assertEqual(
            soup.decode(), self.document_for("QUUX<b>bar</b><a>foo</a>BAZ"))

    def test_insert_after_raises_exception_if_after_has_no_meaning(self):
        soup = self.soup("")
        tag = soup.new_tag("a")
        string = soup.new_string("")
        self.assertRaises(ValueError, string.insert_after, tag)
        self.assertRaises(NotImplementedError, soup.insert_after, tag)
        self.assertRaises(ValueError, tag.insert_after, tag)

    def test_insert_before_raises_notimplementederror_if_before_has_no_meaning(self):
        soup = self.soup("")
        tag = soup.new_tag("a")
        string = soup.new_string("")
        self.assertRaises(ValueError, string.insert_before, tag)
        self.assertRaises(NotImplementedError, soup.insert_before, tag)
        self.assertRaises(ValueError, tag.insert_before, tag)

    def test_replace_with(self):
        soup = self.soup(
                "<p>There's <b>no</b> business like <b>show</b> business</p>")
        no, show = soup.find_all('b')
        show.replace_with(no)
        self.assertEqual(
            soup.decode(),
            self.document_for(
                "<p>There's  business like <b>no</b> business</p>"))

        self.assertEqual(show.parent, None)
        self.assertEqual(no.parent, soup.p)
        self.assertEqual(no.next_element, "no")
        self.assertEqual(no.next_sibling, " business")

    def test_replace_first_child(self):
        data = "<a><b></b><c></c></a>"
        soup = self.soup(data)
        soup.b.replace_with(soup.c)
        self.assertEqual("<a><c></c></a>", soup.decode())

    def test_replace_last_child(self):
        data = "<a><b></b><c></c></a>"
        soup = self.soup(data)
        soup.c.replace_with(soup.b)
        self.assertEqual("<a><b></b></a>", soup.decode())

    def test_nested_tag_replace_with(self):
        soup = self.soup(
            """<a>We<b>reserve<c>the</c><d>right</d></b></a><e>to<f>refuse</f><g>service</g></e>""")

        # Replace the entire <b> tag and its contents ("reserve the
        # right") with the <f> tag ("refuse").
        remove_tag = soup.b
        move_tag = soup.f
        remove_tag.replace_with(move_tag)

        self.assertEqual(
            soup.decode(), self.document_for(
                "<a>We<f>refuse</f></a><e>to<g>service</g></e>"))

        # The <b> tag is now an orphan.
        self.assertEqual(remove_tag.parent, None)
        self.assertEqual(remove_tag.find(text="right").next_element, None)
        self.assertEqual(remove_tag.previous_element, None)
        self.assertEqual(remove_tag.next_sibling, None)
        self.assertEqual(remove_tag.previous_sibling, None)

        # The <f> tag is now connected to the <a> tag.
        self.assertEqual(move_tag.parent, soup.a)
        self.assertEqual(move_tag.previous_element, "We")
        self.assertEqual(move_tag.next_element.next_element, soup.e)
        self.assertEqual(move_tag.next_sibling, None)

        # The gap where the <f> tag used to be has been mended, and
        # the word "to" is now connected to the <g> tag.
        to_text = soup.find(text="to")
        g_tag = soup.g
        self.assertEqual(to_text.next_element, g_tag)
        self.assertEqual(to_text.next_sibling, g_tag)
        self.assertEqual(g_tag.previous_element, to_text)
        self.assertEqual(g_tag.previous_sibling, to_text)

    def test_unwrap(self):
        tree = self.soup("""
            <p>Unneeded <em>formatting</em> is unneeded</p>
            """)
        tree.em.unwrap()
        self.assertEqual(tree.em, None)
        self.assertEqual(tree.p.text, "Unneeded formatting is unneeded")

    def test_wrap(self):
        soup = self.soup("I wish I was bold.")
        value = soup.string.wrap(soup.new_tag("b"))
        self.assertEqual(value.decode(), "<b>I wish I was bold.</b>")
        self.assertEqual(
            soup.decode(), self.document_for("<b>I wish I was bold.</b>"))

    def test_wrap_extracts_tag_from_elsewhere(self):
        soup = self.soup("<b></b>I wish I was bold.")
        soup.b.next_sibling.wrap(soup.b)
        self.assertEqual(
            soup.decode(), self.document_for("<b>I wish I was bold.</b>"))

    def test_wrap_puts_new_contents_at_the_end(self):
        soup = self.soup("<b>I like being bold.</b>I wish I was bold.")
        soup.b.next_sibling.wrap(soup.b)
        self.assertEqual(2, len(soup.b.contents))
        self.assertEqual(
            soup.decode(), self.document_for(
                "<b>I like being bold.I wish I was bold.</b>"))

    def test_extract(self):
        soup = self.soup(
            '<html><body>Some content. <div id="nav">Nav crap</div> More content.</body></html>')

        self.assertEqual(len(soup.body.contents), 3)
        extracted = soup.find(id="nav").extract()

        self.assertEqual(
            soup.decode(), "<html><body>Some content.  More content.</body></html>")
        self.assertEqual(extracted.decode(), '<div id="nav">Nav crap</div>')

        # The extracted tag is now an orphan.
        self.assertEqual(len(soup.body.contents), 2)
        self.assertEqual(extracted.parent, None)
        self.assertEqual(extracted.previous_element, None)
        self.assertEqual(extracted.next_element.next_element, None)

        # The gap where the extracted tag used to be has been mended.
        content_1 = soup.find(text="Some content. ")
        content_2 = soup.find(text=" More content.")
        self.assertEqual(content_1.next_element, content_2)
        self.assertEqual(content_1.next_sibling, content_2)
        self.assertEqual(content_2.previous_element, content_1)
        self.assertEqual(content_2.previous_sibling, content_1)

    def test_extract_distinguishes_between_identical_strings(self):
        soup = self.soup("<a>foo</a><b>bar</b>")
        foo_1 = soup.a.string
        bar_1 = soup.b.string
        foo_2 = soup.new_string("foo")
        bar_2 = soup.new_string("bar")
        soup.a.append(foo_2)
        soup.b.append(bar_2)

        # Now there are two identical strings in the <a> tag, and two
        # in the <b> tag. Let's remove the first "foo" and the second
        # "bar".
        foo_1.extract()
        bar_2.extract()
        self.assertEqual(foo_2, soup.a.string)
        self.assertEqual(bar_2, soup.b.string)

    def test_extract_multiples_of_same_tag(self):
        soup = self.soup("""
<html>
<head>
<script>foo</script>
</head>
<body>
 <script>bar</script>
 <a></a>
</body>
<script>baz</script>
</html>""")
        [soup.script.extract() for i in soup.find_all("script")]
        self.assertEqual("<body>\n\n<a></a>\n</body>", unicode(soup.body))


    def test_extract_works_when_element_is_surrounded_by_identical_strings(self):
        soup = self.soup(
 '<html>\n'
 '<body>hi</body>\n'
 '</html>')
        soup.find('body').extract()
        self.assertEqual(None, soup.find('body'))


    def test_clear(self):
        """Tag.clear()"""
        soup = self.soup("<p><a>String <em>Italicized</em></a> and another</p>")
        # clear using extract()
        a = soup.a
        soup.p.clear()
        self.assertEqual(len(soup.p.contents), 0)
        self.assertTrue(hasattr(a, "contents"))

        # clear using decompose()
        em = a.em
        a.clear(decompose=True)
        self.assertEqual(0, len(em.contents))

    def test_string_set(self):
        """Tag.string = 'string'"""
        soup = self.soup("<a></a> <b><c></c></b>")
        soup.a.string = "foo"
        self.assertEqual(soup.a.contents, ["foo"])
        soup.b.string = "bar"
        self.assertEqual(soup.b.contents, ["bar"])

    def test_string_set_does_not_affect_original_string(self):
        soup = self.soup("<a><b>foo</b><c>bar</c>")
        soup.b.string = soup.c.string
        self.assertEqual(soup.a.encode(), b"<a><b>bar</b><c>bar</c></a>")

    def test_set_string_preserves_class_of_string(self):
        soup = self.soup("<a></a>")
        cdata = CData("foo")
        soup.a.string = cdata
        self.assertTrue(isinstance(soup.a.string, CData))

class TestElementObjects(SoupTest):
    """Test various features of element objects."""

    def test_len(self):
        """The length of an element is its number of children."""
        soup = self.soup("<top>1<b>2</b>3</top>")

        # The BeautifulSoup object itself contains one element: the
        # <top> tag.
        self.assertEqual(len(soup.contents), 1)
        self.assertEqual(len(soup), 1)

        # The <top> tag contains three elements: the text node "1", the
        # <b> tag, and the text node "3".
        self.assertEqual(len(soup.top), 3)
        self.assertEqual(len(soup.top.contents), 3)

    def test_member_access_invokes_find(self):
        """Accessing a Python member .foo invokes find('foo')"""
        soup = self.soup('<b><i></i></b>')
        self.assertEqual(soup.b, soup.find('b'))
        self.assertEqual(soup.b.i, soup.find('b').find('i'))
        self.assertEqual(soup.a, None)

    def test_deprecated_member_access(self):
        soup = self.soup('<b><i></i></b>')
        with warnings.catch_warnings(record=True) as w:
            tag = soup.bTag
        self.assertEqual(soup.b, tag)
        self.assertEqual(
            '.bTag is deprecated, use .find("b") instead.',
            str(w[0].message))

    def test_has_attr(self):
        """has_attr() checks for the presence of an attribute.

        Please note note: has_attr() is different from
        __in__. has_attr() checks the tag's attributes and __in__
        checks the tag's chidlren.
        """
        soup = self.soup("<foo attr='bar'>")
        self.assertTrue(soup.foo.has_attr('attr'))
        self.assertFalse(soup.foo.has_attr('attr2'))


    def test_attributes_come_out_in_alphabetical_order(self):
        markup = '<b a="1" z="5" m="3" f="2" y="4"></b>'
        self.assertSoupEquals(markup, '<b a="1" f="2" m="3" y="4" z="5"></b>')

    def test_string(self):
        # A tag that contains only a text node makes that node
        # available as .string.
        soup = self.soup("<b>foo</b>")
        self.assertEqual(soup.b.string, 'foo')

    def test_empty_tag_has_no_string(self):
        # A tag with no children has no .stirng.
        soup = self.soup("<b></b>")
        self.assertEqual(soup.b.string, None)

    def test_tag_with_multiple_children_has_no_string(self):
        # A tag with no children has no .string.
        soup = self.soup("<a>foo<b></b><b></b></b>")
        self.assertEqual(soup.b.string, None)

        soup = self.soup("<a>foo<b></b>bar</b>")
        self.assertEqual(soup.b.string, None)

        # Even if all the children are strings, due to trickery,
        # it won't work--but this would be a good optimization.
        soup = self.soup("<a>foo</b>")
        soup.a.insert(1, "bar")
        self.assertEqual(soup.a.string, None)

    def test_tag_with_recursive_string_has_string(self):
        # A tag with a single child which has a .string inherits that
        # .string.
        soup = self.soup("<a><b>foo</b></a>")
        self.assertEqual(soup.a.string, "foo")
        self.assertEqual(soup.string, "foo")

    def test_lack_of_string(self):
        """Only a tag containing a single text node has a .string."""
        soup = self.soup("<b>f<i>e</i>o</b>")
        self.assertFalse(soup.b.string)

        soup = self.soup("<b></b>")
        self.assertFalse(soup.b.string)

    def test_all_text(self):
        """Tag.text and Tag.get_text(sep=u"") -> all child text, concatenated"""
        soup = self.soup("<a>a<b>r</b>   <r> t </r></a>")
        self.assertEqual(soup.a.text, "ar  t ")
        self.assertEqual(soup.a.get_text(strip=True), "art")
        self.assertEqual(soup.a.get_text(","), "a,r, , t ")
        self.assertEqual(soup.a.get_text(",", strip=True), "a,r,t")

    def test_get_text_ignores_comments(self):
        soup = self.soup("foo<!--IGNORE-->bar")
        self.assertEqual(soup.get_text(), "foobar")

        self.assertEqual(
            soup.get_text(types=(NavigableString, Comment)), "fooIGNOREbar")
        self.assertEqual(
            soup.get_text(types=None), "fooIGNOREbar")

    def test_all_strings_ignores_comments(self):
        soup = self.soup("foo<!--IGNORE-->bar")
        self.assertEqual(['foo', 'bar'], list(soup.strings))

class TestCDAtaListAttributes(SoupTest):

    """Testing cdata-list attributes like 'class'.
    """
    def test_single_value_becomes_list(self):
        soup = self.soup("<a class='foo'>")
        self.assertEqual(["foo"],soup.a['class'])

    def test_multiple_values_becomes_list(self):
        soup = self.soup("<a class='foo bar'>")
        self.assertEqual(["foo", "bar"], soup.a['class'])

    def test_multiple_values_separated_by_weird_whitespace(self):
        soup = self.soup("<a class='foo\tbar\nbaz'>")
        self.assertEqual(["foo", "bar", "baz"],soup.a['class'])

    def test_attributes_joined_into_string_on_output(self):
        soup = self.soup("<a class='foo\tbar'>")
        self.assertEqual(b'<a class="foo bar"></a>', soup.a.encode())

    def test_accept_charset(self):
        soup = self.soup('<form accept-charset="ISO-8859-1 UTF-8">')
        self.assertEqual(['ISO-8859-1', 'UTF-8'], soup.form['accept-charset'])

    def test_cdata_attribute_applying_only_to_one_tag(self):
        data = '<a accept-charset="ISO-8859-1 UTF-8"></a>'
        soup = self.soup(data)
        # We saw in another test that accept-charset is a cdata-list
        # attribute for the <form> tag. But it's not a cdata-list
        # attribute for any other tag.
        self.assertEqual('ISO-8859-1 UTF-8', soup.a['accept-charset'])

    def test_string_has_immutable_name_property(self):
        string = self.soup("s").string
        self.assertEqual(None, string.name)
        def t():
            string.name = 'foo'
        self.assertRaises(AttributeError, t)

class TestPersistence(SoupTest):
    "Testing features like pickle and deepcopy."

    def setUp(self):
        super(TestPersistence, self).setUp()
        self.page = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN"
"http://www.w3.org/TR/REC-html40/transitional.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Beautiful Soup: We called him Tortoise because he taught us.</title>
<link rev="made" href="mailto:leonardr@segfault.org">
<meta name="Description" content="Beautiful Soup: an HTML parser optimized for screen-scraping.">
<meta name="generator" content="Markov Approximation 1.4 (module: leonardr)">
<meta name="author" content="Leonard Richardson">
</head>
<body>
<a href="foo">foo</a>
<a href="foo"><b>bar</b></a>
</body>
</html>"""
        self.tree = self.soup(self.page)

    def test_pickle_and_unpickle_identity(self):
        # Pickling a tree, then unpickling it, yields a tree identical
        # to the original.
        dumped = pickle.dumps(self.tree, 2)
        loaded = pickle.loads(dumped)
        self.assertEqual(loaded.__class__, BeautifulSoup)
        self.assertEqual(loaded.decode(), self.tree.decode())

    def test_deepcopy_identity(self):
        # Making a deepcopy of a tree yields an identical tree.
        copied = copy.deepcopy(self.tree)
        self.assertEqual(copied.decode(), self.tree.decode())

    def test_unicode_pickle(self):
        # A tree containing Unicode characters can be pickled.
        html = u"<b>\N{SNOWMAN}</b>"
        soup = self.soup(html)
        dumped = pickle.dumps(soup, pickle.HIGHEST_PROTOCOL)
        loaded = pickle.loads(dumped)
        self.assertEqual(loaded.decode(), soup.decode())

    def test_copy_navigablestring_is_not_attached_to_tree(self):
        html = u"<b>Foo<a></a></b><b>Bar</b>"
        soup = self.soup(html)
        s1 = soup.find(string="Foo")
        s2 = copy.copy(s1)
        self.assertEqual(s1, s2)
        self.assertEqual(None, s2.parent)
        self.assertEqual(None, s2.next_element)
        self.assertNotEqual(None, s1.next_sibling)
        self.assertEqual(None, s2.next_sibling)
        self.assertEqual(None, s2.previous_element)

    def test_copy_navigablestring_subclass_has_same_type(self):
        html = u"<b><!--Foo--></b>"
        soup = self.soup(html)
        s1 = soup.string
        s2 = copy.copy(s1)
        self.assertEqual(s1, s2)
        self.assertTrue(isinstance(s2, Comment))

    def test_copy_entire_soup(self):
        html = u"<div><b>Foo<a></a></b><b>Bar</b></div>end"
        soup = self.soup(html)
        soup_copy = copy.copy(soup)
        self.assertEqual(soup, soup_copy)

    def test_copy_tag_copies_contents(self):
        html = u"<div><b>Foo<a></a></b><b>Bar</b></div>end"
        soup = self.soup(html)
        div = soup.div
        div_copy = copy.copy(div)

        # The two tags look the same, and evaluate to equal.
        self.assertEqual(unicode(div), unicode(div_copy))
        self.assertEqual(div, div_copy)

        # But they're not the same object.
        self.assertFalse(div is div_copy)

        # And they don't have the same relation to the parse tree. The
        # copy is not associated with a parse tree at all.
        self.assertEqual(None, div_copy.parent)
        self.assertEqual(None, div_copy.previous_element)
        self.assertEqual(None, div_copy.find(string='Bar').next_element)
        self.assertNotEqual(None, div.find(string='Bar').next_element)

class TestSubstitutions(SoupTest):

    def test_default_formatter_is_minimal(self):
        markup = u"<b>&lt;&lt;Sacr\N{LATIN SMALL LETTER E WITH ACUTE} bleu!&gt;&gt;</b>"
        soup = self.soup(markup)
        decoded = soup.decode(formatter="minimal")
        # The < is converted back into &lt; but the e-with-acute is left alone.
        self.assertEqual(
            decoded,
            self.document_for(
                u"<b>&lt;&lt;Sacr\N{LATIN SMALL LETTER E WITH ACUTE} bleu!&gt;&gt;</b>"))

    def test_formatter_html(self):
        markup = u"<b>&lt;&lt;Sacr\N{LATIN SMALL LETTER E WITH ACUTE} bleu!&gt;&gt;</b>"
        soup = self.soup(markup)
        decoded = soup.decode(formatter="html")
        self.assertEqual(
            decoded,
            self.document_for("<b>&lt;&lt;Sacr&eacute; bleu!&gt;&gt;</b>"))

    def test_formatter_minimal(self):
        markup = u"<b>&lt;&lt;Sacr\N{LATIN SMALL LETTER E WITH ACUTE} bleu!&gt;&gt;</b>"
        soup = self.soup(markup)
        decoded = soup.decode(formatter="minimal")
        # The < is converted back into &lt; but the e-with-acute is left alone.
        self.assertEqual(
            decoded,
            self.document_for(
                u"<b>&lt;&lt;Sacr\N{LATIN SMALL LETTER E WITH ACUTE} bleu!&gt;&gt;</b>"))

    def test_formatter_null(self):
        markup = u"<b>&lt;&lt;Sacr\N{LATIN SMALL LETTER E WITH ACUTE} bleu!&gt;&gt;</b>"
        soup = self.soup(markup)
        decoded = soup.decode(formatter=None)
        # Neither the angle brackets nor the e-with-acute are converted.
        # This is not valid HTML, but it's what the user wanted.
        self.assertEqual(decoded,
                          self.document_for(u"<b><<Sacr\N{LATIN SMALL LETTER E WITH ACUTE} bleu!>></b>"))

    def test_formatter_custom(self):
        markup = u"<b>&lt;foo&gt;</b><b>bar</b>"
        soup = self.soup(markup)
        decoded = soup.decode(formatter = lambda x: x.upper())
        # Instead of normal entity conversion code, the custom
        # callable is called on every string.
        self.assertEqual(
            decoded,
            self.document_for(u"<b><FOO></b><b>BAR</b>"))

    def test_formatter_is_run_on_attribute_values(self):
        markup = u'<a href="http://a.com?a=b&c=é">e</a>'
        soup = self.soup(markup)
        a = soup.a

        expect_minimal = u'<a href="http://a.com?a=b&amp;c=é">e</a>'

        self.assertEqual(expect_minimal, a.decode())
        self.assertEqual(expect_minimal, a.decode(formatter="minimal"))

        expect_html = u'<a href="http://a.com?a=b&amp;c=&eacute;">e</a>'
        self.assertEqual(expect_html, a.decode(formatter="html"))

        self.assertEqual(markup, a.decode(formatter=None))
        expect_upper = u'<a href="HTTP://A.COM?A=B&C=É">E</a>'
        self.assertEqual(expect_upper, a.decode(formatter=lambda x: x.upper()))

    def test_formatter_skips_script_tag_for_html_documents(self):
        doc = """
  <script type="text/javascript">
   console.log("< < hey > > ");
  </script>
"""
        encoded = BeautifulSoup(doc, 'html.parser').encode()
        self.assertTrue(b"< < hey > >" in encoded)

    def test_formatter_skips_style_tag_for_html_documents(self):
        doc = """
  <style type="text/css">
   console.log("< < hey > > ");
  </style>
"""
        encoded = BeautifulSoup(doc, 'html.parser').encode()
        self.assertTrue(b"< < hey > >" in encoded)

    def test_prettify_leaves_preformatted_text_alone(self):
        soup = self.soup("<div>  foo  <pre>  \tbar\n  \n  </pre>  baz  ")
        # Everything outside the <pre> tag is reformatted, but everything
        # inside is left alone.
        self.assertEqual(
            u'<div>\n foo\n <pre>  \tbar\n  \n  </pre>\n baz\n</div>',
            soup.div.prettify())

    def test_prettify_accepts_formatter(self):
        soup = BeautifulSoup("<html><body>foo</body></html>", 'html.parser')
        pretty = soup.prettify(formatter = lambda x: x.upper())
        self.assertTrue("FOO" in pretty)

    def test_prettify_outputs_unicode_by_default(self):
        soup = self.soup("<a></a>")
        self.assertEqual(unicode, type(soup.prettify()))

    def test_prettify_can_encode_data(self):
        soup = self.soup("<a></a>")
        self.assertEqual(bytes, type(soup.prettify("utf-8")))

    def test_html_entity_substitution_off_by_default(self):
        markup = u"<b>Sacr\N{LATIN SMALL LETTER E WITH ACUTE} bleu!</b>"
        soup = self.soup(markup)
        encoded = soup.b.encode("utf-8")
        self.assertEqual(encoded, markup.encode('utf-8'))

    def test_encoding_substitution(self):
        # Here's the <meta> tag saying that a document is
        # encoded in Shift-JIS.
        meta_tag = ('<meta content="text/html; charset=x-sjis" '
                    'http-equiv="Content-type"/>')
        soup = self.soup(meta_tag)

        # Parse the document, and the charset apprears unchanged.
        self.assertEqual(soup.meta['content'], 'text/html; charset=x-sjis')

        # Encode the document into some encoding, and the encoding is
        # substituted into the meta tag.
        utf_8 = soup.encode("utf-8")
        self.assertTrue(b"charset=utf-8" in utf_8)

        euc_jp = soup.encode("euc_jp")
        self.assertTrue(b"charset=euc_jp" in euc_jp)

        shift_jis = soup.encode("shift-jis")
        self.assertTrue(b"charset=shift-jis" in shift_jis)

        utf_16_u = soup.encode("utf-16").decode("utf-16")
        self.assertTrue("charset=utf-16" in utf_16_u)

    def test_encoding_substitution_doesnt_happen_if_tag_is_strained(self):
        markup = ('<head><meta content="text/html; charset=x-sjis" '
                    'http-equiv="Content-type"/></head><pre>foo</pre>')

        # Beautiful Soup used to try to rewrite the meta tag even if the
        # meta tag got filtered out by the strainer. This test makes
        # sure that doesn't happen.
        strainer = SoupStrainer('pre')
        soup = self.soup(markup, parse_only=strainer)
        self.assertEqual(soup.contents[0].name, 'pre')

class TestEncoding(SoupTest):
    """Test the ability to encode objects into strings."""

    def test_unicode_string_can_be_encoded(self):
        html = u"<b>\N{SNOWMAN}</b>"
        soup = self.soup(html)
        self.assertEqual(soup.b.string.encode("utf-8"),
                          u"\N{SNOWMAN}".encode("utf-8"))

    def test_tag_containing_unicode_string_can_be_encoded(self):
        html = u"<b>\N{SNOWMAN}</b>"
        soup = self.soup(html)
        self.assertEqual(
            soup.b.encode("utf-8"), html.encode("utf-8"))

    def test_encoding_substitutes_unrecognized_characters_by_default(self):
        html = u"<b>\N{SNOWMAN}</b>"
        soup = self.soup(html)
        self.assertEqual(soup.b.encode("ascii"), b"<b>&#9731;</b>")

    def test_encoding_can_be_made_strict(self):
        html = u"<b>\N{SNOWMAN}</b>"
        soup = self.soup(html)
        self.assertRaises(
            UnicodeEncodeError, soup.encode, "ascii", errors="strict")

    def test_decode_contents(self):
        html = u"<b>\N{SNOWMAN}</b>"
        soup = self.soup(html)
        self.assertEqual(u"\N{SNOWMAN}", soup.b.decode_contents())

    def test_encode_contents(self):
        html = u"<b>\N{SNOWMAN}</b>"
        soup = self.soup(html)
        self.assertEqual(
            u"\N{SNOWMAN}".encode("utf8"), soup.b.encode_contents(
                encoding="utf8"))

    def test_deprecated_renderContents(self):
        html = u"<b>\N{SNOWMAN}</b>"
        soup = self.soup(html)
        self.assertEqual(
            u"\N{SNOWMAN}".encode("utf8"), soup.b.renderContents())

    def test_repr(self):
        html = u"<b>\N{SNOWMAN}</b>"
        soup = self.soup(html)
        if PY3K:
            self.assertEqual(html, repr(soup))
        else:
            self.assertEqual(b'<b>\\u2603</b>', repr(soup))

class TestNavigableStringSubclasses(SoupTest):

    def test_cdata(self):
        # None of the current builders turn CDATA sections into CData
        # objects, but you can create them manually.
        soup = self.soup("")
        cdata = CData("foo")
        soup.insert(1, cdata)
        self.assertEqual(str(soup), "<![CDATA[foo]]>")
        self.assertEqual(soup.find(text="foo"), "foo")
        self.assertEqual(soup.contents[0], "foo")

    def test_cdata_is_never_formatted(self):
        """Text inside a CData object is passed into the formatter.

        But the return value is ignored.
        """

        self.count = 0
        def increment(*args):
            self.count += 1
            return "BITTER FAILURE"

        soup = self.soup("")
        cdata = CData("<><><>")
        soup.insert(1, cdata)
        self.assertEqual(
            b"<![CDATA[<><><>]]>", soup.encode(formatter=increment))
        self.assertEqual(1, self.count)

    def test_doctype_ends_in_newline(self):
        # Unlike other NavigableString subclasses, a DOCTYPE always ends
        # in a newline.
        doctype = Doctype("foo")
        soup = self.soup("")
        soup.insert(1, doctype)
        self.assertEqual(soup.encode(), b"<!DOCTYPE foo>\n")

    def test_declaration(self):
        d = Declaration("foo")
        self.assertEqual("<?foo?>", d.output_ready())

class TestSoupSelector(TreeTest):

    HTML = """
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
"http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<title>The title</title>
<link rel="stylesheet" href="blah.css" type="text/css" id="l1">
</head>
<body>
<custom-dashed-tag class="dashed" id="dash1">Hello there.</custom-dashed-tag>
<div id="main" class="fancy">
<div id="inner">
<h1 id="header1">An H1</h1>
<p>Some text</p>
<p class="onep" id="p1">Some more text</p>
<h2 id="header2">An H2</h2>
<p class="class1 class2 class3" id="pmulti">Another</p>
<a href="http://bob.example.org/" rel="friend met" id="bob">Bob</a>
<h2 id="header3">Another H2</h2>
<a id="me" href="http://simonwillison.net/" rel="me">me</a>
<span class="s1">
<a href="#" id="s1a1">span1a1</a>
<a href="#" id="s1a2">span1a2 <span id="s1a2s1">test</span></a>
<span class="span2">
<a href="#" id="s2a1">span2a1</a>
</span>
<span class="span3"></span>
<custom-dashed-tag class="dashed" id="dash2"/>
<div data-tag="dashedvalue" id="data1"/>
</span>
</div>
<x id="xid">
<z id="zida"/>
<z id="zidab"/>
<z id="zidac"/>
</x>
<y id="yid">
<z id="zidb"/>
</y>
<p lang="en" id="lang-en">English</p>
<p lang="en-gb" id="lang-en-gb">English UK</p>
<p lang="en-us" id="lang-en-us">English US</p>
<p lang="fr" id="lang-fr">French</p>
</div>

<div id="footer">
</div>
"""

    def setUp(self):
        self.soup = BeautifulSoup(self.HTML, 'html.parser')

    def assertSelects(self, selector, expected_ids):
        el_ids = [el['id'] for el in self.soup.select(selector)]
        el_ids.sort()
        expected_ids.sort()
        self.assertEqual(expected_ids, el_ids,
            "Selector %s, expected [%s], got [%s]" % (
                selector, ', '.join(expected_ids), ', '.join(el_ids)
            )
        )

    assertSelect = assertSelects

    def assertSelectMultiple(self, *tests):
        for selector, expected_ids in tests:
            self.assertSelect(selector, expected_ids)

    def test_one_tag_one(self):
        els = self.soup.select('title')
        self.assertEqual(len(els), 1)
        self.assertEqual(els[0].name, 'title')
        self.assertEqual(els[0].contents, [u'The title'])

    def test_one_tag_many(self):
        els = self.soup.select('div')
        self.assertEqual(len(els), 4)
        for div in els:
            self.assertEqual(div.name, 'div')

        el = self.soup.select_one('div')
        self.assertEqual('main', el['id'])

    def test_select_one_returns_none_if_no_match(self):
        match = self.soup.select_one('nonexistenttag')
        self.assertEqual(None, match)


    def test_tag_in_tag_one(self):
        els = self.soup.select('div div')
        self.assertSelects('div div', ['inner', 'data1'])

    def test_tag_in_tag_many(self):
        for selector in ('html div', 'html body div', 'body div'):
            self.assertSelects(selector, ['data1', 'main', 'inner', 'footer'])

    def test_tag_no_match(self):
        self.assertEqual(len(self.soup.select('del')), 0)

    def test_invalid_tag(self):
        self.assertRaises(ValueError, self.soup.select, 'tag%t')

    def test_select_dashed_tag_ids(self):
        self.assertSelects('custom-dashed-tag', ['dash1', 'dash2'])

    def test_select_dashed_by_id(self):
        dashed = self.soup.select('custom-dashed-tag[id=\"dash2\"]')
        self.assertEqual(dashed[0].name, 'custom-dashed-tag')
        self.assertEqual(dashed[0]['id'], 'dash2')

    def test_dashed_tag_text(self):
        self.assertEqual(self.soup.select('body > custom-dashed-tag')[0].text, u'Hello there.')

    def test_select_dashed_matches_find_all(self):
        self.assertEqual(self.soup.select('custom-dashed-tag'), self.soup.find_all('custom-dashed-tag'))

    def test_header_tags(self):
        self.assertSelectMultiple(
            ('h1', ['header1']),
            ('h2', ['header2', 'header3']),
        )

    def test_class_one(self):
        for selector in ('.onep', 'p.onep', 'html p.onep'):
            els = self.soup.select(selector)
            self.assertEqual(len(els), 1)
            self.assertEqual(els[0].name, 'p')
            self.assertEqual(els[0]['class'], ['onep'])

    def test_class_mismatched_tag(self):
        els = self.soup.select('div.onep')
        self.assertEqual(len(els), 0)

    def test_one_id(self):
        for selector in ('div#inner', '#inner', 'div div#inner'):
            self.assertSelects(selector, ['inner'])

    def test_bad_id(self):
        els = self.soup.select('#doesnotexist')
        self.assertEqual(len(els), 0)

    def test_items_in_id(self):
        els = self.soup.select('div#inner p')
        self.assertEqual(len(els), 3)
        for el in els:
            self.assertEqual(el.name, 'p')
        self.assertEqual(els[1]['class'], ['onep'])
        self.assertFalse(els[0].has_attr('class'))

    def test_a_bunch_of_emptys(self):
        for selector in ('div#main del', 'div#main div.oops', 'div div#main'):
            self.assertEqual(len(self.soup.select(selector)), 0)

    def test_multi_class_support(self):
        for selector in ('.class1', 'p.class1', '.class2', 'p.class2',
            '.class3', 'p.class3', 'html p.class2', 'div#inner .class2'):
            self.assertSelects(selector, ['pmulti'])

    def test_multi_class_selection(self):
        for selector in ('.class1.class3', '.class3.class2',
                         '.class1.class2.class3'):
            self.assertSelects(selector, ['pmulti'])

    def test_child_selector(self):
        self.assertSelects('.s1 > a', ['s1a1', 's1a2'])
        self.assertSelects('.s1 > a span', ['s1a2s1'])

    def test_child_selector_id(self):
        self.assertSelects('.s1 > a#s1a2 span', ['s1a2s1'])

    def test_attribute_equals(self):
        self.assertSelectMultiple(
            ('p[class="onep"]', ['p1']),
            ('p[id="p1"]', ['p1']),
            ('[class="onep"]', ['p1']),
            ('[id="p1"]', ['p1']),
            ('link[rel="stylesheet"]', ['l1']),
            ('link[type="text/css"]', ['l1']),
            ('link[href="blah.css"]', ['l1']),
            ('link[href="no-blah.css"]', []),
            ('[rel="stylesheet"]', ['l1']),
            ('[type="text/css"]', ['l1']),
            ('[href="blah.css"]', ['l1']),
            ('[href="no-blah.css"]', []),
            ('p[href="no-blah.css"]', []),
            ('[href="no-blah.css"]', []),
        )

    def test_attribute_tilde(self):
        self.assertSelectMultiple(
            ('p[class~="class1"]', ['pmulti']),
            ('p[class~="class2"]', ['pmulti']),
            ('p[class~="class3"]', ['pmulti']),
            ('[class~="class1"]', ['pmulti']),
            ('[class~="class2"]', ['pmulti']),
            ('[class~="class3"]', ['pmulti']),
            ('a[rel~="friend"]', ['bob']),
            ('a[rel~="met"]', ['bob']),
            ('[rel~="friend"]', ['bob']),
            ('[rel~="met"]', ['bob']),
        )

    def test_attribute_startswith(self):
        self.assertSelectMultiple(
            ('[rel^="style"]', ['l1']),
            ('link[rel^="style"]', ['l1']),
            ('notlink[rel^="notstyle"]', []),
            ('[rel^="notstyle"]', []),
            ('link[rel^="notstyle"]', []),
            ('link[href^="bla"]', ['l1']),
            ('a[href^="http://"]', ['bob', 'me']),
            ('[href^="http://"]', ['bob', 'me']),
            ('[id^="p"]', ['pmulti', 'p1']),
            ('[id^="m"]', ['me', 'main']),
            ('div[id^="m"]', ['main']),
            ('a[id^="m"]', ['me']),
            ('div[data-tag^="dashed"]', ['data1'])
        )

    def test_attribute_endswith(self):
        self.assertSelectMultiple(
            ('[href$=".css"]', ['l1']),
            ('link[href$=".css"]', ['l1']),
            ('link[id$="1"]', ['l1']),
            ('[id$="1"]', ['data1', 'l1', 'p1', 'header1', 's1a1', 's2a1', 's1a2s1', 'dash1']),
            ('div[id$="1"]', ['data1']),
            ('[id$="noending"]', []),
        )

    def test_attribute_contains(self):
        self.assertSelectMultiple(
            # From test_attribute_startswith
            ('[rel*="style"]', ['l1']),
            ('link[rel*="style"]', ['l1']),
            ('notlink[rel*="notstyle"]', []),
            ('[rel*="notstyle"]', []),
            ('link[rel*="notstyle"]', []),
            ('link[href*="bla"]', ['l1']),
            ('[href*="http://"]', ['bob', 'me']),
            ('[id*="p"]', ['pmulti', 'p1']),
            ('div[id*="m"]', ['main']),
            ('a[id*="m"]', ['me']),
            # From test_attribute_endswith
            ('[href*=".css"]', ['l1']),
            ('link[href*=".css"]', ['l1']),
            ('link[id*="1"]', ['l1']),
            ('[id*="1"]', ['data1', 'l1', 'p1', 'header1', 's1a1', 's1a2', 's2a1', 's1a2s1', 'dash1']),
            ('div[id*="1"]', ['data1']),
            ('[id*="noending"]', []),
            # New for this test
            ('[href*="."]', ['bob', 'me', 'l1']),
            ('a[href*="."]', ['bob', 'me']),
            ('link[href*="."]', ['l1']),
            ('div[id*="n"]', ['main', 'inner']),
            ('div[id*="nn"]', ['inner']),
            ('div[data-tag*="edval"]', ['data1'])
        )

    def test_attribute_exact_or_hypen(self):
        self.assertSelectMultiple(
            ('p[lang|="en"]', ['lang-en', 'lang-en-gb', 'lang-en-us']),
            ('[lang|="en"]', ['lang-en', 'lang-en-gb', 'lang-en-us']),
            ('p[lang|="fr"]', ['lang-fr']),
            ('p[lang|="gb"]', []),
        )

    def test_attribute_exists(self):
        self.assertSelectMultiple(
            ('[rel]', ['l1', 'bob', 'me']),
            ('link[rel]', ['l1']),
            ('a[rel]', ['bob', 'me']),
            ('[lang]', ['lang-en', 'lang-en-gb', 'lang-en-us', 'lang-fr']),
            ('p[class]', ['p1', 'pmulti']),
            ('[blah]', []),
            ('p[blah]', []),
            ('div[data-tag]', ['data1'])
        )

    def test_unsupported_pseudoclass(self):
        self.assertRaises(
            NotImplementedError, self.soup.select, "a:no-such-pseudoclass")

        self.assertRaises(
            NotImplementedError, self.soup.select, "a:nth-of-type(a)")


    def test_nth_of_type(self):
        # Try to select first paragraph
        els = self.soup.select('div#inner p:nth-of-type(1)')
        self.assertEqual(len(els), 1)
        self.assertEqual(els[0].string, u'Some text')

        # Try to select third paragraph
        els = self.soup.select('div#inner p:nth-of-type(3)')
        self.assertEqual(len(els), 1)
        self.assertEqual(els[0].string, u'Another')

        # Try to select (non-existent!) fourth paragraph
        els = self.soup.select('div#inner p:nth-of-type(4)')
        self.assertEqual(len(els), 0)

        # Pass in an invalid value.
        self.assertRaises(
            ValueError, self.soup.select, 'div p:nth-of-type(0)')

    def test_nth_of_type_direct_descendant(self):
        els = self.soup.select('div#inner > p:nth-of-type(1)')
        self.assertEqual(len(els), 1)
        self.assertEqual(els[0].string, u'Some text')

    def test_id_child_selector_nth_of_type(self):
        self.assertSelects('#inner > p:nth-of-type(2)', ['p1'])

    def test_select_on_element(self):
        # Other tests operate on the tree; this operates on an element
        # within the tree.
        inner = self.soup.find("div", id="main")
        selected = inner.select("div")
        # The <div id="inner"> tag was selected. The <div id="footer">
        # tag was not.
        self.assertSelectsIDs(selected, ['inner', 'data1'])

    def test_overspecified_child_id(self):
        self.assertSelects(".fancy #inner", ['inner'])
        self.assertSelects(".normal #inner", [])

    def test_adjacent_sibling_selector(self):
        self.assertSelects('#p1 + h2', ['header2'])
        self.assertSelects('#p1 + h2 + p', ['pmulti'])
        self.assertSelects('#p1 + #header2 + .class1', ['pmulti'])
        self.assertEqual([], self.soup.select('#p1 + p'))

    def test_general_sibling_selector(self):
        self.assertSelects('#p1 ~ h2', ['header2', 'header3'])
        self.assertSelects('#p1 ~ #header2', ['header2'])
        self.assertSelects('#p1 ~ h2 + a', ['me'])
        self.assertSelects('#p1 ~ h2 + [rel="me"]', ['me'])
        self.assertEqual([], self.soup.select('#inner ~ h2'))

    def test_dangling_combinator(self):
        self.assertRaises(ValueError, self.soup.select, 'h1 >')

    def test_sibling_combinator_wont_select_same_tag_twice(self):
        self.assertSelects('p[lang] ~ p', ['lang-en-gb', 'lang-en-us', 'lang-fr'])

    # Test the selector grouping operator (the comma)
    def test_multiple_select(self):
        self.assertSelects('x, y', ['xid', 'yid'])

    def test_multiple_select_with_no_space(self):
        self.assertSelects('x,y', ['xid', 'yid'])

    def test_multiple_select_with_more_space(self):
        self.assertSelects('x,    y', ['xid', 'yid'])

    def test_multiple_select_duplicated(self):
        self.assertSelects('x, x', ['xid'])

    def test_multiple_select_sibling(self):
        self.assertSelects('x, y ~ p[lang=fr]', ['xid', 'lang-fr'])

    def test_multiple_select_tag_and_direct_descendant(self):
        self.assertSelects('x, y > z', ['xid', 'zidb'])

    def test_multiple_select_direct_descendant_and_tags(self):
        self.assertSelects('div > x, y, z', ['xid', 'yid', 'zida', 'zidb', 'zidab', 'zidac'])

    def test_multiple_select_indirect_descendant(self):
        self.assertSelects('div x,y,  z', ['xid', 'yid', 'zida', 'zidb', 'zidab', 'zidac'])

    def test_invalid_multiple_select(self):
        self.assertRaises(ValueError, self.soup.select, ',x, y')
        self.assertRaises(ValueError, self.soup.select, 'x,,y')

    def test_multiple_select_attrs(self):
        self.assertSelects('p[lang=en], p[lang=en-gb]', ['lang-en', 'lang-en-gb'])

    def test_multiple_select_ids(self):
        self.assertSelects('x, y > z[id=zida], z[id=zidab], z[id=zidb]', ['xid', 'zidb', 'zidab'])

    def test_multiple_select_nested(self):
        self.assertSelects('body > div > x, y > z', ['xid', 'zidb'])




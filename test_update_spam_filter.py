#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import unittest

import update_spam_filter


class update_spam_filter:
    pass


class usfTest(object):
    cls = None

    def setUp(self):
        self.instance = self.cls()

    def test_escape_regexp_symbols_return_string_for_regexp(self):
        """Return a string"""
        self.assertIsInstance(self.instance.escape_regexp_symbols("[a-z\\.-]"), str)

    def test_escape_regexp_symbols_only_strings(self):
        """Return false if not a string"""
        self.assertFalse(
            self.instance.escape_regexp_symbols(42),
            msg="An integer should not be escaped",
        )
        self.assertFalse(
            self.instance.escape_regexp_symbols(1.2),
            msg="A double should not be escaped",
        )
        self.assertFalse(
            self.instance.escape_regexp_symbols(list()),
            msg="A list should not be escaped",
        )
        self.assertFalse(
            self.instance.escape_regexp_symbols(dict()),
            msg="A dictionary should not be escaped",
        )

    def test_is_excluded_mta_is_false_for_non_existing_mta(self):
        """Check if return false with a non existing MTA"""
        sample_config = dict()
        sample_config["excluded_mtas"] = ("uno", "dos", "tres")
        self.assertFalse(
            self.instance.is_excluded_mta("this is not an MTA", sample_config)
        )

    def test_is_junk_not_dict(self):
        """Return false if not a message structure?"""
        self.assertFalse(
            self.instance.is_junk("a"), msg="A simple string should not be Junk"
        )
        self.assertFalse(self.instance.is_junk(42), msg="An integer should not be Junk")
        self.assertFalse(self.instance.is_junk(1.2), msg="A double should not be Junk")
        self.assertFalse(self.instance.is_junk(list()), msg="A list should not be Junk")

    def test_is_junk_sample_message(self):
        """Test with a sample message"""
        message = dict()
        message[0] = dict()
        message[0][0] = " Junk"
        self.assertTrue(self.instance.is_junk(message))


class usfTestParent(usfTest, unittest.TestCase):
    """Tests for `update_spam_filter`"""

    cls = update_spam_filter


if __name__ == "__main__":
    unittest.main()

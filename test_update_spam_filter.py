#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import unittest
from update_spam_filter import escape_regexp_symbols, is_excluded_mta, is_junk


class escape_regexp_symbols_test_case(unittest.TestCase):
    """Tests for `escape_regexp_symbols`"""

    def test_escape_regexp_symbols_return_string_for_regexp(self):
        """Return a string"""
        self.assertIsInstance(escape_regexp_symbols("[a-z\\.-]"), str)

    def test_escape_regexp_symbols_only_strings(self):
        """Return false if not a string"""
        self.assertFalse(
            escape_regexp_symbols(42), msg="An integer should not be escaped"
        )
        self.assertFalse(
            escape_regexp_symbols(1.2), msg="A double should not be escaped"
        )
        self.assertFalse(
            escape_regexp_symbols(list()), msg="A list should not be escaped"
        )
        self.assertFalse(
            escape_regexp_symbols(dict()), msg="A dictionary should not be escaped"
        )


class is_excluded_mta_test_case(unittest.TestCase):
    """Tests for `is_excluded_mta`"""

    def test_is_excluded_mta_is_false_for_non_existing_mta(self):
        """Check if return false with a non existing MTA"""
        sample_config = dict()
        sample_config["excluded_mtas"] = ("uno", "dos", "tres")
        self.assertFalse(is_excluded_mta("this is not an MTA", sample_config))


class is_junk_test_case(unittest.TestCase):
    """Tests for `is_junk`"""

    def test_is_junk_not_dict(self):
        """Return false if not a message structure?"""
        self.assertFalse(is_junk("a"), msg="A simple string should not be Junk")
        self.assertFalse(is_junk(42), msg="An integer should not be Junk")
        self.assertFalse(is_junk(1.2), msg="A double should not be Junk")
        self.assertFalse(is_junk(list()), msg="A list should not be Junk")

    def test_is_junk_sample_message(self):
        """Test with a sample message"""
        message = dict()
        message[0] = dict()
        message[0][0] = " Junk"
        self.assertTrue(is_junk(message))


if __name__ == "__main__":
    unittest.main()

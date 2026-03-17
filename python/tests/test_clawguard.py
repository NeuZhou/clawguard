"""Tests for ClawGuard Python bindings."""

import unittest
import sys
import os

# Add parent dir to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from clawguard import __version__, ClawGuardError


class TestClawGuardModule(unittest.TestCase):
    """Test ClawGuard Python module structure."""

    def test_version_exists(self):
        """Module should have a version string."""
        self.assertIsInstance(__version__, str)
        self.assertRegex(__version__, r'\d+\.\d+\.\d+')

    def test_exports(self):
        """Module should export core functions."""
        import clawguard
        self.assertTrue(callable(clawguard.scan))
        self.assertTrue(callable(clawguard.check))
        self.assertTrue(callable(clawguard.sanitize))

    def test_error_class(self):
        """ClawGuardError should be an Exception."""
        self.assertTrue(issubclass(ClawGuardError, Exception))

    def test_all_exports(self):
        """__all__ should list public API."""
        import clawguard
        self.assertIn('scan', clawguard.__all__)
        self.assertIn('check', clawguard.__all__)
        self.assertIn('sanitize', clawguard.__all__)
        self.assertIn('ClawGuardError', clawguard.__all__)


if __name__ == '__main__':
    unittest.main()

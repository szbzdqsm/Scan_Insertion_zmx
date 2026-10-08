from pathlib import Path
import hashlib
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from original_dofile import copy_original_dofile, read_original_text
from artifact_operations import independent_copy


class OriginalDofileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "original.dofile"
        self.execution = self.root / "run" / "R1.dofile"
        self.delivery = self.root / "deliver" / "R1.dofile"
        self.execution.parent.mkdir()
        self.delivery.parent.mkdir()

    def digest(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def assert_copies(self, payload):
        self.source.write_bytes(payload)
        before = self.source.stat()
        self.assertEqual(copy_original_dofile(self.source, self.execution, self.delivery),
                         (self.execution, self.delivery))
        self.assertEqual({self.digest(path) for path in [self.source, self.execution, self.delivery]},
                         {hashlib.sha256(payload).hexdigest()})
        self.assertEqual(self.source.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(len({path.stat().st_ino for path in [self.source, self.execution, self.delivery]}), 3)
        self.execution.write_bytes(b"changed execution")
        self.assertEqual(self.source.read_bytes(), payload)
        self.assertEqual(self.delivery.read_bytes(), payload)
        self.delivery.write_bytes(b"changed delivery")
        self.assertEqual(self.source.read_bytes(), payload)

    def test_complete_script_over_50k_retains_tail_for_context_and_execution(self):
        payload = (b"# synthetic script comment\n" * 5000) + b"set final_marker hidden_ending\nexit\n"
        self.assertGreater(len(payload), 50000)
        self.assert_copies(payload)
        text = read_original_text(self.source)
        self.assertEqual(text.encode(), payload)
        self.assertIn("set final_marker hidden_ending\nexit\n", text)

    def test_crlf_lf_and_cr_are_never_normalized(self):
        payload = b"load_lib sample.lib\r\npresent_design fresh\n# comment\rexit\r\n"
        self.assert_copies(payload)
        self.assertEqual(read_original_text(self.source).encode(), payload)

    def test_utf8_bom_is_retained_in_text_and_both_raw_copies(self):
        payload = b"\xef\xbb\xbf# original BOM\r\nexit\r\n"
        self.assert_copies(payload)
        text = read_original_text(self.source)
        self.assertTrue(text.startswith("\ufeff"))
        self.assertEqual(text.encode(), payload)

    def test_non_utf8_comment_is_replaced_only_for_context_not_copies(self):
        payload = b"# legacy encoded comment: \x81\xff\xfe\r\nexit\r\n"
        self.assert_copies(payload)
        text = read_original_text(self.source)
        self.assertIn("\ufffd", text)
        self.assertTrue(text.endswith("exit\r\n"))
        self.assertNotEqual(text.encode(), payload)

    def test_same_source_destination_is_rejected_before_any_copy(self):
        self.source.write_bytes(b"untouched")
        with self.assertRaises(ValueError):
            copy_original_dofile(self.source, self.execution, self.source)
        self.assertEqual(self.source.read_bytes(), b"untouched")
        self.assertFalse(self.execution.exists())

    def test_hardlinked_source_destination_is_rejected_before_other_copy(self):
        self.source.write_bytes(b"untouched")
        os.link(self.source, self.delivery)
        with self.assertRaises(ValueError):
            copy_original_dofile(self.source, self.execution, self.delivery)
        self.assertEqual(self.source.read_bytes(), b"untouched")
        self.assertFalse(self.execution.exists())

    def test_destination_symlink_to_source_is_rejected_before_other_copy(self):
        self.source.write_bytes(b"untouched")
        self.delivery.symlink_to(self.source)
        with self.assertRaises(ValueError):
            copy_original_dofile(self.source, self.execution, self.delivery)
        self.assertEqual(self.source.read_bytes(), b"untouched")
        self.assertFalse(self.execution.exists())

    def test_alias_through_parent_symlink_cannot_overwrite_source(self):
        self.source.write_bytes(b"untouched")
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            copy_original_dofile(self.source, self.execution, alias / self.source.name)
        self.assertEqual(self.source.read_bytes(), b"untouched")
        self.assertFalse(self.execution.exists())

    def test_two_output_aliases_are_rejected_before_writing(self):
        self.source.write_bytes(b"untouched")
        with self.assertRaises(ValueError):
            copy_original_dofile(self.source, self.execution, self.execution.parent / "." / self.execution.name)
        self.assertFalse(self.execution.exists())
        self.execution.write_bytes(b"old copy")
        os.link(self.execution, self.delivery)
        with self.assertRaises(ValueError):
            copy_original_dofile(self.source, self.execution, self.delivery)
        self.assertEqual(self.execution.read_bytes(), b"old copy")

    def test_destination_directory_and_missing_parent_are_rejected_before_copy(self):
        self.source.write_bytes(b"untouched")
        for invalid in [self.delivery.parent, self.root / "missing" / "R1.dofile"]:
            with self.subTest(invalid=invalid), self.assertRaises((ValueError, FileNotFoundError)):
                copy_original_dofile(self.source, self.execution, invalid)
            self.assertFalse(self.execution.exists())

    def test_symlink_source_is_read_and_copied_without_modifying_the_link(self):
        self.source.write_bytes(b"original bytes\r\n")
        link = self.root / "original-link.dofile"
        link.symlink_to(self.source)
        self.assertEqual(read_original_text(link), "original bytes\r\n")
        copy_original_dofile(link, self.execution, self.delivery)
        self.assertTrue(link.is_symlink())
        self.assertEqual(self.execution.read_bytes(), self.source.read_bytes())

    def test_source_change_during_copy_prevents_successful_return(self):
        self.source.write_bytes(b"original bytes")
        calls = 0

        def changing_copy(source, destination):
            nonlocal calls
            result = independent_copy(source, destination)
            calls += 1
            if calls == 1:
                self.source.write_bytes(b"modified bytes")
            return result

        with patch("original_dofile.independent_copy", side_effect=changing_copy), self.assertRaises(RuntimeError):
            copy_original_dofile(self.source, self.execution, self.delivery)


if __name__ == "__main__":
    unittest.main()

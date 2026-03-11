"""
tests/test_utils.py - Unit tests for utils.py
"""
import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from utils import human_size, validate_code, save_file_securely, ProgressBar


class TestHumanSize:
    def test_bytes(self):
        assert human_size(512) == "512.00 B"

    def test_kilobytes(self):
        assert human_size(1024) == "1.00 KB"

    def test_megabytes(self):
        assert "MB" in human_size(1024 * 1024)

    def test_gigabytes(self):
        assert "GB" in human_size(1024 ** 3)


class TestValidateCode:
    def test_valid_two_word_code(self):
        assert validate_code("7-plum-snowflake") is True

    def test_valid_three_word_code(self):
        assert validate_code("42-apple-thunder-rain") is True

    def test_invalid_no_digit_prefix(self):
        assert validate_code("plum-snowflake") is False

    def test_invalid_empty(self):
        assert validate_code("") is False

    def test_invalid_spaces(self):
        assert validate_code("7 plum snowflake") is False

    def test_valid_with_trailing_whitespace(self):
        # strip() is called inside validate_code
        assert validate_code("  7-plum-snowflake  ") is True


class TestSaveFileSecurely:
    def test_saves_content(self):
        data = b"hello anonshare"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = save_file_securely(data, "testfile.txt", tmpdir)
            with open(path, "rb") as fh:
                assert fh.read() == data

    def test_creates_output_directory(self):
        data = b"content"
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = os.path.join(tmpdir, "subdir", "nested")
            path = save_file_securely(data, "f.bin", subdir)
            assert os.path.exists(path)

    def test_filename_basename_only(self):
        """Path traversal: only the basename of the filename is used."""
        data = b"safe"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = save_file_securely(data, "../../../etc/passwd", tmpdir)
            # The file must land inside tmpdir, not at /etc/passwd
            assert os.path.commonpath([path, tmpdir]) == tmpdir

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")
    def test_permissions_600(self):
        data = b"secret"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = save_file_securely(data, "secret.bin", tmpdir)
            mode = oct(os.stat(path).st_mode)[-3:]
            assert mode == "600"


class TestProgressBar:
    def test_finish_without_crash(self, capsys):
        pb = ProgressBar(total=1024, label="Test")
        pb.update(512)
        pb.update(512)
        pb.finish()
        # Should not raise; output goes to stderr

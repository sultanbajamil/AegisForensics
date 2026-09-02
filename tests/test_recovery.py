import os
import struct
import unittest
import tempfile
from aegis_forensics.plugins.file_recovery import parse_dollar_i_file


class TestFileRecovery(unittest.TestCase):
    def setUp(self):
        # Create a mock $I Version 2 metadata file
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_file_path = self.temp_file.name
        
        # Structure specs for Windows 10/11 $I (Version 2):
        # - Header: 8 bytes (value = 2)
        # - File size: 8 bytes (value = 20480)
        # - Filetime: 8 bytes (value = 132539000000000000 -> 2021-01-01 approx)
        # - Path len: 4 bytes (value = len("C:\\secrets.txt"))
        # - Path: UTF-16LE encoded path
        
        header = 2
        file_size = 20480
        # 132539000000000000 corresponds to: (132539000000000000 - 116444736000000000) / 10000000 = 1609459200 Unix (2021-01-01 UTC)
        filetime = 132539000000000000
        
        original_path = "C:\\secrets.txt"
        path_bytes = original_path.encode("utf-16-le") + b"\x00\x00"
        path_len = len(original_path) + 1  # includes null-terminator character count
        
        # Build binary packet
        # Q = unsigned 64-bit, I = unsigned 32-bit
        metadata_bytes = struct.pack("<QQQI", header, file_size, filetime, path_len) + path_bytes
        self.temp_file.write(metadata_bytes)
        self.temp_file.close()

    def tearDown(self):
        if os.path.exists(self.temp_file_path):
            os.remove(self.temp_file_path)

    def test_parse_dollar_i_metadata(self):
        meta = parse_dollar_i_file(self.temp_file_path)
        
        # Validate extracted metadata
        self.assertEqual(meta["version"], 2)
        self.assertEqual(meta["file_size"], 20480)
        self.assertEqual(meta["original_path"], "C:\\secrets.txt")
        self.assertEqual(meta["original_name"], "secrets.txt")
        self.assertEqual(meta["deletion_time"], "2020-12-31 14:53:20 UTC")


if __name__ == "__main__":
    unittest.main()

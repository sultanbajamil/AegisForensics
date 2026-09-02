import os
import unittest
import tempfile
from aegis_forensics.core.memory import carve_memory_generator


class TestMemoryCarver(unittest.TestCase):
    def setUp(self):
        # Create a mock memory dump file containing various forensic patterns
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".raw")
        self.temp_file_path = self.temp_file.name
        
        # Binary data block with hidden strings
        self.mock_data = (
            b"Some garbage data in RAM...\x00\x00\xff"
            b"User logged in from IP address: 192.168.1.55 inside system"
            b"\x00\x12Some metadata http://malicious-c2-domain.com/shell.exe"
            b" and also an email address support@bank-leak.xyz on the line."
            b"AWS token details: AKIAIOSFODNN7EXAMPLE is active."
            b"-----BEGIN RSA PRIVATE KEY-----\n"
            b"MIIEowIBAAKCAQEA0x...KeyMaterial...\n"
            b"-----END RSA PRIVATE KEY-----\n"
            b"Invalid IP 999.888.777.666 and another invalid ip 256.0.0.1"
        )
        self.temp_file.write(self.mock_data)
        self.temp_file.close()

    def tearDown(self):
        if os.path.exists(self.temp_file_path):
            os.remove(self.temp_file_path)

    def test_carver_finds_patterns(self):
        carver = carve_memory_generator(self.temp_file_path, chunk_size=1024, overlap_size=128)
        results = {}
        for update in carver:
            if update["status"] == "complete":
                results = update["results"]
                
        # Validate extracted elements
        self.assertIn("192.168.1.55", results.get("ips", []))
        self.assertNotIn("999.888.777.666", results.get("ips", []))
        self.assertNotIn("256.0.0.1", results.get("ips", []))
        
        self.assertIn("http://malicious-c2-domain.com/shell.exe", results.get("urls", []))
        self.assertIn("support@bank-leak.xyz", results.get("emails", []))
        self.assertIn("AKIAIOSFODNN7EXAMPLE", results.get("aws_keys", []))
        self.assertIn("-----BEGIN RSA PRIVATE KEY-----", results.get("private_keys", []))


if __name__ == "__main__":
    unittest.main()

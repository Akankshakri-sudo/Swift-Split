"""
Comprehensive test suite for SecureVault engine, cloud, and API server.
"""

import os
import shutil
import tempfile
import unittest
from fastapi.testclient import TestClient

import engine
import cloud
from main import app, VAULT_DIR, MERGE_DIR, UPLOAD_DIR


class TestEngineMath(unittest.TestCase):
    def test_gf256_operations(self):
        # Multiplication identity and inverse
        self.assertEqual(engine._gmul(1, 42), 42)
        self.assertEqual(engine._gmul(0, 255), 0)
        inv = engine._ginv(42)
        self.assertEqual(engine._gmul(42, inv), 1)

    def test_shamir_secret_sharing(self):
        key = b"\x01" * 32
        k, n = 3, 5
        shares = engine.split_secret(key, k, n)
        self.assertEqual(len(shares), n)

        # Reconstruct with exact k shares (indices 0, 1, 2)
        recovered = engine.combine_secret(shares[:k])
        self.assertEqual(recovered, key)

        # Reconstruct with different subset of k shares (indices 1, 3, 4)
        subset = [shares[1], shares[3], shares[4]]
        recovered_subset = engine.combine_secret(subset)
        self.assertEqual(recovered_subset, key)

        # Fail with duplicate share index
        with self.assertRaises(engine.EngineError):
            engine.combine_secret([shares[0], shares[0], shares[1]])

    def test_reed_solomon_erasure_coding(self):
        data = b"Hello SecureVault Reed-Solomon Erasure Coding Test Payload!"
        k, n = 3, 5
        shards = engine._rs_encode(data, n, k)
        self.assertEqual(len(shards), n)

        # Test all C(5, 3) = 10 combinations of 3 shards
        from itertools import combinations
        for combo in combinations(range(n), k):
            present = {i: shards[i] for i in combo}
            reconstructed = engine._rs_decode(present, n, k)[:len(data)]
            self.assertEqual(reconstructed, data, f"Failed for shard combination {combo}")


class TestEngineSplitMerge(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="svtest_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_split_and_merge_modes(self):
        sample_data = b"Confidential data payload for splitting and merging." * 10
        src_path = os.path.join(self.test_dir, "sample.bin")
        with open(src_path, "wb") as f:
            f.write(sample_data)

        modes = [
            (engine.MODE_NONE, ""),
            (engine.MODE_PASSWORD, "SecretPass123"),
            (engine.MODE_SHAMIR, ""),
        ]

        for mode, password in modes:
            out_dir = os.path.join(self.test_dir, f"out_{mode}")
            manifest = engine.split_file(src_path, out_dir, parts=4, threshold=3, mode=mode, password=password)
            self.assertEqual(manifest["parts"], 4)
            self.assertEqual(manifest["threshold"], 3)
            self.assertEqual(manifest["mode"], mode)

            frag_paths = [os.path.join(out_dir, f["name"]) for f in manifest["fragments"]]

            # Test reconstruction with exact 3 shards (threshold)
            merged_path = os.path.join(self.test_dir, f"merged_{mode}.bin")
            result = engine.merge_fragments(frag_paths[:3], merged_path, password=password)
            self.assertEqual(result["integrity"], "verified")
            with open(merged_path, "rb") as f:
                self.assertEqual(f.read(), sample_data)

            # Test threshold failure (< 3 shards)
            with self.assertRaises(engine.EngineError):
                engine.merge_fragments(frag_paths[:2], merged_path, password=password)

            # Test wrong password in password mode
            if mode == engine.MODE_PASSWORD:
                with self.assertRaises(engine.EngineError):
                    engine.merge_fragments(frag_paths[:3], merged_path, password="WrongPassword")

    def test_legacy_enc_merge(self):
        # Test OpenSSL legacy .enc merge
        plain_text = b"Legacy OpenSSL AES-256-CBC test content."
        part1 = os.path.join(self.test_dir, "test.txt_part1.enc")
        part2 = os.path.join(self.test_dir, "test.txt_part2.enc")

        key, iv = engine._evp_bytes_to_key("mypass")
        enc1 = engine._aes_cbc_encrypt(key, iv, plain_text[:20])
        enc2 = engine._aes_cbc_encrypt(key, iv, plain_text[20:])

        with open(part1, "wb") as f:
            f.write(enc1)
        with open(part2, "wb") as f:
            f.write(enc2)

        merged_out = os.path.join(self.test_dir, "legacy_merged.txt")
        result = engine.merge_legacy_enc([part1, part2], merged_out, "mypass")
        self.assertEqual(result["format"], "legacy-openssl")
        with open(merged_out, "rb") as f:
            self.assertEqual(f.read(), plain_text)


class TestAPIRoutes(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_and_stats(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["version"], "2.0")

        stats_resp = self.client.get("/api/stats")
        self.assertEqual(stats_resp.status_code, 200)

    def test_split_and_merge_api(self):
        file_content = b"FastAPI split and merge integration test content."
        files = {"file": ("test_doc.txt", file_content, "text/plain")}
        data = {"parts": "4", "threshold": "3", "mode": "shamir"}

        split_resp = self.client.post("/api/split", files=files, data=data)
        self.assertEqual(split_resp.status_code, 200)
        split_json = split_resp.json()
        set_info = split_json["set"]
        set_id = set_info["id"]

        # Download fragments
        fragments = set_info["fragments"]
        self.assertEqual(len(fragments), 4)

        downloaded_frags = []
        for frag in fragments[:3]:
            res = self.client.get(frag["url"])
            self.assertEqual(res.status_code, 200)
            downloaded_frags.append((frag["name"], res.content))

        # Merge back using API
        merge_files = [("files", (name, content, "application/octet-stream")) for name, content in downloaded_frags]
        merge_resp = self.client.post("/api/merge", files=merge_files)
        self.assertEqual(merge_resp.status_code, 200)
        merge_json = merge_resp.json()
        self.assertEqual(merge_json["result"]["integrity"], "verified")

        # Cleanup set
        del_resp = self.client.delete(f"/api/vault/{set_id}")
        self.assertEqual(del_resp.status_code, 200)

    def test_legacy_enc_merge_api(self):
        plain_text = b"Legacy .enc API upload test payload."
        key, iv = engine._evp_bytes_to_key("mypass")
        enc1 = engine._aes_cbc_encrypt(key, iv, plain_text[:15])
        enc2 = engine._aes_cbc_encrypt(key, iv, plain_text[15:])

        files = [
            ("files", ("test.txt_part1.enc", enc1, "application/octet-stream")),
            ("files", ("test.txt_part2.enc", enc2, "application/octet-stream")),
        ]
        data = {"password": "mypass"}

        response = self.client.post("/api/merge", files=files, data=data)
        self.assertEqual(response.status_code, 200)
        json_resp = response.json()
        self.assertIn("Reconstructed 'test.txt'", json_resp["message"])


if __name__ == "__main__":
    unittest.main()

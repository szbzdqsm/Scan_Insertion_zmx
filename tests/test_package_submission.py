import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile


_SCRIPT = Path(__file__).resolve().parents[1] / "scripts/package_submission.py"
_SPEC = importlib.util.spec_from_file_location("package_submission", _SCRIPT)
package = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(package)


class PackageSubmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "fixture"
        self.agent = self.repo / "agent"
        self.agent.mkdir(parents=True)
        self.dockerfile = ("FROM scan-agent-base:ubuntu24\n"
                           "COPY requirements.txt /tmp/requirements.txt\n"
                           "COPY agent_system /submission/agent_system\n"
                           "COPY scan_agent.py /submission/scan_agent.py\n"
                           "COPY helper.py /submission/helper.py\n"
                           "RUN chmod +x /submission/agent_system\n"
                           'ENTRYPOINT ["/submission/agent_system"]\n')
        for name, data in {"Dockerfile": self.dockerfile, "requirements.txt": "dependency\n",
                           "agent_system": "#!/bin/sh\nexec python3 /submission/scan_agent.py \"$@\"\n",
                           "scan_agent.py": "import helper\n", "helper.py": "value = 1\n",
                           ".env": "PRIVATE_SENTINEL_ONLY\n", "unrelated.py": "not used\n",
                           "赛题指南.docx": "excluded\n", "old.log": "excluded\n",
                           "golden.dofile": "excluded\n", "preset_issues.json": "{}\n"}.items():
            (self.agent / name).write_text(data)
        self.output = Path(self.temp.name) / "package"

    def build(self, directory=None):
        return package.build_submission(directory or self.output, repo_root=self.repo)

    def test_official_layout_copy_paths_permissions_and_source_hashes(self):
        result = self.build()
        self.assertEqual(set(result), {"zip_path", "stage_path"})
        with zipfile.ZipFile(result["zip_path"]) as archive:
            self.assertEqual(set(archive.namelist()), {"Dockerfile", ".env", ".dockerignore", "README.md",
                                                      "SOURCE_MANIFEST.json", "submission/agent_system",
                                                      "submission/scan_agent.py", "submission/helper.py",
                                                      "submission/requirements.txt"})
            rewritten = archive.read("Dockerfile").decode()
            self.assertIn("COPY submission/helper.py /submission/helper.py", rewritten)
            self.assertIn("COPY submission/requirements.txt /tmp/requirements.txt", rewritten)
            self.assertEqual(archive.getinfo("submission/agent_system").external_attr >> 16, 0o100755)
            self.assertEqual(archive.getinfo(".env").external_attr >> 16, 0o100600)
            manifest = json.loads(archive.read("SOURCE_MANIFEST.json"))
            helper = next(item for item in manifest["source_files"] if item["source"] == "agent/helper.py")
            self.assertEqual(helper["sha256"], hashlib.sha256(b"value = 1\n").hexdigest())
            self.assertFalse(manifest["uploaded"])
        self.assertEqual(stat.S_IMODE((result["stage_path"] / "submission/agent_system").stat().st_mode), 0o755)

    def test_private_env_is_never_read_and_generated_env_is_outside_image_context(self):
        original_open = Path.open
        private = self.agent / ".env"

        def guarded_open(path, *args, **kwargs):
            if path == private:
                raise AssertionError("Private environment file was accessed")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", guarded_open):
            result = self.build()
        with zipfile.ZipFile(result["zip_path"]) as archive:
            env = archive.read(".env").decode()
            self.assertIn("LLM_API_KEY=\n", env)
            self.assertNotIn("PRIVATE_SENTINEL_ONLY", env)
            self.assertEqual(archive.read(".dockerignore").decode(), "**\n!Dockerfile\n!submission/\n!submission/**\n")
            self.assertIn("not been uploaded", archive.read("README.md").decode())

    def test_existing_output_is_not_overwritten(self):
        self.output.mkdir()
        marker = self.output / "keep.txt"
        marker.write_text("preserve")
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual(marker.read_text(), "preserve")
        self.assertEqual(list(self.output.iterdir()), [marker])

    def test_only_runtime_copy_sources_are_allowed(self):
        for declaration in ["COPY .env /submission/.env\n", "COPY ../private.py /submission/private.py\n",
                            "COPY golden.dofile /submission/golden.dofile\n",
                            "COPY 赛题指南.docx /submission/guide.docx\n",
                            "COPY old.log /submission/old.log\n"]:
            with self.subTest(declaration=declaration):
                (self.agent / "Dockerfile").write_text(self.dockerfile + declaration)
                with self.assertRaises(ValueError):
                    self.build()
                self.assertFalse(self.output.exists())

    def test_source_change_produces_a_new_manifest_without_touching_old_package(self):
        first = self.build()
        first_bytes = first["zip_path"].read_bytes()
        (self.agent / "helper.py").write_text("value = 2\n")
        second = self.build(Path(self.temp.name) / "new-package")
        self.assertEqual(first["zip_path"].read_bytes(), first_bytes)
        with zipfile.ZipFile(second["zip_path"]) as archive:
            manifest = json.loads(archive.read("SOURCE_MANIFEST.json"))
            helper = next(item for item in manifest["source_files"] if item["source"] == "agent/helper.py")
            self.assertEqual(helper["sha256"], hashlib.sha256(b"value = 2\n").hexdigest())
            self.assertEqual(archive.read("submission/helper.py"), b"value = 2\n")


if __name__ == "__main__":
    unittest.main()

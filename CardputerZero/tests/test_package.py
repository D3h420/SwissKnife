import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CARDPUTER = ROOT / "CardputerZero"


class PackageTests(unittest.TestCase):
    def test_manifest_and_non_root_launcher(self):
        manifest = json.loads((CARDPUTER / "app-builder.json").read_text())
        metadata = (CARDPUTER / "packaging/meta.env").read_text()
        self.assertEqual(manifest["package_name"], "swissknife-cardputer")
        self.assertIn("APP_TERMINAL=false", metadata)
        self.assertNotIn("User=root", metadata)
        self.assertTrue((CARDPUTER / "packaging/icon.png").is_file())

    def test_stage_has_one_copy_of_shared_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            env = {**os.environ, "STAGE": str(stage), "APP_INSTALL_DIR": "/usr/share/APPLaunch/apps/swissknife-cardputer", "INSTALL_PREFIX": "/usr/share/APPLaunch"}
            subprocess.run(["bash", str(CARDPUTER / "packaging/stage.sh")], env=env, check=True)
            installed = stage / "usr/share/APPLaunch/apps/swissknife-cardputer"
            self.assertTrue((installed / "core/engine.py").exists())
            self.assertTrue((installed / "modules/recon.py").exists())
            self.assertFalse((installed / "CardputerZero/modules").exists())
            self.assertTrue((stage / "usr/share/APPLaunch/bin/swissknife-cardputer").exists())


if __name__ == "__main__":
    unittest.main()

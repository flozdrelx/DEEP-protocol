"""Release packaging must preserve runtime assets without bundling local secrets."""
import json
from pathlib import Path
import tempfile
import unittest
import release

class ReleaseTests(unittest.TestCase):
    def test_desktop_payload_requires_matching_build_and_excludes_user_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            files={
                "DEEP.Viewer.exe":b"exe","DEEP.Viewer.dll":b"dll",
                "DEEP.Viewer.runtimeconfig.json":b"{}","runtime.dll":b"runtime","icudtl.dat":b"data",
                "licenses/DEEP-LICENSE.txt":b"license",
                "config.json":b"private configuration","identity.key":b"secret",
                "Profile.WebView2/Cookies":b"session","unexpected/config.json":b"secret"
            }
            for name,data in files.items():
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            deps={"runtimeTarget":{"name":".NETCoreApp,Version=v10.0/win-x64"},"libraries":{"DEEP.Viewer/3.0.0":{}}}
            (root/"DEEP.Viewer.deps.json").write_text(json.dumps(deps))
            payload=release.viewer_payloads(root,"3.0.0")
            self.assertIn("bin/viewer/runtime.dll",payload)
            self.assertIn("bin/viewer/icudtl.dat",payload)
            self.assertIn("bin/viewer/licenses/DEEP-LICENSE.txt",payload)
            self.assertNotIn("bin/viewer/config.json",payload)
            self.assertFalse(any(b"secret" in data or b"session" in data for data,_ in payload.values()))
            with self.assertRaises(ValueError):release.viewer_payloads(root,"2.3.3")
            deps["runtimeTarget"]["name"]=".NETCoreApp,Version=v10.0/win-arm64"
            (root/"DEEP.Viewer.deps.json").write_text(json.dumps(deps))
            with self.assertRaises(ValueError):release.viewer_payloads(root,"3.0.0")

    def test_source_contains_policy_tests_and_no_generated_profiles(self):
        payload=release.source_payloads()
        self.assertIn("viewer/DEEP.Viewer.PolicyTests/Program.cs",payload)
        self.assertIn("v3_regression_test.go",payload)
        self.assertFalse(any("/obj/" in p or "/bin/" in p or p.endswith(".key") for p in payload))

if __name__=="__main__":unittest.main()

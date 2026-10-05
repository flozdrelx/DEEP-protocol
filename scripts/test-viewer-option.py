#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify opt-in viewer behavior and the headless integration interface."""
import argparse,json,os,pathlib,subprocess,tempfile
from smoke_test import RunningNode, run_command
ROOT=pathlib.Path(__file__).resolve().parent.parent
FLAGS={"creationflags":subprocess.CREATE_NO_WINDOW} if os.name=="nt" else {}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deep",type=pathlib.Path,default=ROOT/"bin/deep.exe")
    parser.add_argument("--viewer",type=pathlib.Path,default=ROOT/"bin/viewer/DEEP.Viewer.exe")
    args=parser.parse_args()
    deep=str(args.deep.resolve())
    checks=[]
    def command(*argv,ok=True,input_data=None):
        result=subprocess.run([deep,*argv],input=input_data,capture_output=True,timeout=30,**FLAGS)
        if (result.returncode==0)!=ok:raise RuntimeError(result.stderr.decode("utf-8","replace"))
        return result
    with tempfile.TemporaryDirectory(prefix="deep-viewer-option-") as temp:
        root=pathlib.Path(temp)
        os.environ["APPDATA"]=str(root/"preferences")
        os.environ["XDG_CONFIG_HOME"]=os.environ["APPDATA"]
        # macOS stores preferences below HOME, ignoring APPDATA and XDG_CONFIG_HOME.
        os.environ["HOME"]=str(root)
        state=json.loads(command("viewer","status","--json").stdout)
        settings=pathlib.Path(state["settings"]).resolve()
        assert settings.is_relative_to(root.resolve()), "Viewer settings escaped the temporary directory"
        assert not state["enabled"]
        assert not settings.exists()
        for verb in ("browse","open-uri"):
            result=command(verb,"deep://demo.test/",ok=False)
            assert b"disabled" in result.stderr
        checks.append("disabled_by_default_without_preferences_or_fetch")
        # Headless request mode is the same interface another browser can use.
        node=RunningNode(deep,root/"node","demo.test",public=True)
        try:
            expected=b"Headless DEEP integration works.\n"
            (node.directory/"content/index.txt").write_bytes(expected)
            result=command("request","deep://demo.test/","--config",str(node.client_config),"--info",
                input_data=json.dumps({"method":"GET","headers":[],"body":""}).encode())
            assert result.stdout==expected
            metadata=json.loads(result.stderr)
            assert metadata["status"]==200 and metadata["security"]["post_quantum_authentication"]
            checks.append("verified_application_request_without_viewer")
        finally:node.close()
        if os.name=="nt":
            report=root/"disabled.json"
            result=subprocess.run([str(args.viewer.resolve()),"--deep",deep,"--test-report",str(report)],capture_output=True,timeout=20,**FLAGS)
            assert result.returncode!=0 and "disabled" in json.loads(report.read_text(encoding="utf-8"))["error"]
            checks.append("direct_companion_launch_respects_disabled_setting")
            command("viewer","enable")
            assert json.loads(command("viewer","status","--json").stdout)["enabled"]
            command("viewer","disable")
            assert not json.loads(command("viewer","status","--json").stdout)["enabled"]
            checks.append("enable_disable_persist_across_processes")
        else:
            command("viewer","enable",ok=False)
        print(json.dumps({"ok":True,"checks":checks},indent=2))
if __name__=="__main__":main()

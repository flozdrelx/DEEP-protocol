#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the Windows renderer against a temporary, authenticated local DEEP site."""
import argparse,json,os,pathlib,queue,shutil,subprocess,tempfile,threading
ROOT=pathlib.Path(__file__).resolve().parent.parent

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deep",type=pathlib.Path,default=ROOT/"bin/deep.exe")
    parser.add_argument("--viewer",type=pathlib.Path,default=ROOT/"bin/viewer/DEEP.Viewer.exe")
    parser.add_argument("--report",type=pathlib.Path,required=True)
    args=parser.parse_args()
    args.report=args.report.resolve()
    if args.report.exists(): parser.error("Choose a new report path.")
    startup=subprocess.STARTUPINFO()
    startup.dwFlags|=subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow=0
    hidden={"startupinfo":startup,"creationflags":subprocess.CREATE_NO_WINDOW}
    with tempfile.TemporaryDirectory(prefix="deep-viewer-test-") as temp:
        # Isolate opt-in preferences from the user's real DEEP installation.
        os.environ["APPDATA"]=str(pathlib.Path(temp)/"preferences")
        os.environ["XDG_CONFIG_HOME"]=os.environ["APPDATA"]
        subprocess.run([str(args.deep.resolve()),"viewer","enable"],check=True,capture_output=True,**hidden)
        node=pathlib.Path(temp)/"node"
        subprocess.run([str(args.deep),"init","--authority","demo.test","--dir",str(node),"--address","127.0.0.1:9761"],check=True,capture_output=True,**hidden)
        shutil.copytree(ROOT/"examples/website",node/"content",dirs_exist_ok=True)
        # Use a locally installed font only inside this temporary test. It is
        # never copied into the project or distributed with release artifacts.
        shutil.copyfile(pathlib.Path(os.environ["WINDIR"])/"Fonts/arial.ttf",node/"content/assets/test-font.ttf")
        css=node/"content/assets/site.css"
        with css.open("a",encoding="utf-8") as out: out.write("\n@font-face{font-family:DeepTest;src:url('./test-font.ttf')}#data-status{font-family:DeepTest,sans-serif}\n")
        settings=json.loads((node/"server.json").read_text(encoding="utf-8"))
        settings["listen"]="127.0.0.1:0"
        (node/"server.json").write_text(json.dumps(settings),encoding="utf-8")
        server=subprocess.Popen([str(args.deep),"serve","--config",str(node/"server.json")],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,**hidden)
        try:
            lines=queue.Queue()
            threading.Thread(target=lambda: [lines.put(line) for line in server.stdout],daemon=True).start()
            line=lines.get(timeout=15)
            if " listening on " not in line: raise RuntimeError(line)
            address=line.split(" listening on ",1)[1].split(" for ",1)[0]
            config=json.loads((node/"client.json").read_text(encoding="utf-8"))
            config["networks"]["test"]["endpoints"]["demo.test"]["address"]=address
            (node/"client.json").write_text(json.dumps(config),encoding="utf-8")
            command=[str(args.viewer),"--deep",str(args.deep.resolve()),"--config",str(node/"client.json"),"--uri","deep://demo.test/","--test-report",str(args.report)]
            process=subprocess.Popen(command,**hidden)
            try: code=process.wait(timeout=150)
            finally:
                if process.poll() is None: process.kill();process.wait(timeout=10)
            if not args.report.exists(): raise RuntimeError(f"Viewer exited with {code} without a report.")
            report=json.loads(args.report.read_text(encoding="utf-8"))
            print(json.dumps(report,indent=2))
            if code!=0 or not report.get("ok"): raise SystemExit(1)
            wrong=config["networks"]["test"]["endpoints"]["demo.test"]
            wrong["pin_sha256"]="0"*64 if wrong["pin_sha256"]!="0"*64 else "1"*64
            (node/"wrong-pin.json").write_text(json.dumps(config),encoding="utf-8")
            rejected=args.report.with_name(args.report.stem+"-rejection.json")
            reject_command=[str(args.viewer),"--deep",str(args.deep.resolve()),"--config",str(node/"wrong-pin.json"),"--uri","deep://demo.test/","--test-report",str(rejected),"--test-expect","rejection"]
            process=subprocess.Popen(reject_command,**hidden)
            try: code=process.wait(timeout=45)
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=10)
            rejection=json.loads(rejected.read_text(encoding="utf-8"))
            print(json.dumps(rejection,indent=2))
            if code!=0 or not rejection.get("ok"):raise SystemExit(1)
        finally:
            server.terminate()
            try:server.wait(timeout=10)
            except subprocess.TimeoutExpired:server.kill();server.wait(timeout=10)
if __name__=="__main__":main()

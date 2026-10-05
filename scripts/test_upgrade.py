#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check both directions of release compatibility using temporary private identities."""
import argparse
from pathlib import Path
import tempfile
from smoke_test import RunningNode, run_command, verify_file

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous",required=True,type=Path)
    parser.add_argument("--current",required=True,type=Path)
    args=parser.parse_args()
    previous,current=args.previous.resolve(),args.current.resolve()
    with tempfile.TemporaryDirectory(prefix="deep-upgrade-") as temporary:
        root=Path(temporary)
        for index,(server,client) in enumerate(((previous,current),(current,previous))):
            with RunningNode(server,root/f"node-{index}","upgrade.test") as node:
                output=root/f"result-{index}.txt"
                run_command([client,"fetch","deep://upgrade.test/","--config",node.client_config,
                             "--output",output,"--info"],"cross-release private transfer")
                verify_file(output,(node.directory/"content/index.txt").read_bytes())
    print("PASS: previous-client/current-server and current-client/previous-server with private identities and unchanged configuration.")

if __name__=="__main__":main()

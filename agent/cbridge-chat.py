#!/usr/bin/env python3
"""CanberraAI shared-password terminal chat client."""
import argparse, asyncio, getpass, json, os, sys, urllib.request
from pathlib import Path
import websockets

CONFIG=Path.home()/".config"/"cbridge-chat.json"

def api(server,path,payload):
    req=urllib.request.Request(server.rstrip("/") + path,
        data=json.dumps(payload).encode(),headers={"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(req,timeout=15) as r: return json.load(r)

def pair(args):
    password=args.password or getpass.getpass("Shared pairing password [default C1nb3rr1]: ")
    if not password: password="C1nb3rr1"
    result=api(args.server,"/api/chat/pair",{"name":args.name,"password":password})
    CONFIG.parent.mkdir(parents=True,exist_ok=True)
    CONFIG.write_text(json.dumps({"server":args.server.rstrip("/"),**result}))
    os.chmod(CONFIG,0o600)
    print(f"Paired as {result['name']} ({result['device_id']}). Credentials saved to {CONFIG}")

async def run():
    if not CONFIG.exists():
        print("Not paired. Run: cbridge-chat pair --server https://your-domain --name This-PC"); return
    cfg=json.loads(CONFIG.read_text())
    server=cfg["server"].replace("https://","wss://").replace("http://","ws://")
    url=f"{server}/ws/chat?device_id={cfg['device_id']}&token={cfg['device_token']}"
    async with websockets.connect(url,max_size=2**20) as ws:
        current=None
        print(f"Connected as {cfg['name']}. Commands: /users, /to DEVICE_ID, /quit")
        async def receive():
            async for raw in ws:
                m=json.loads(raw)
                if m.get("type") in ("welcome","presence"):
                    print("\nONLINE DEVICES:")
                    for d in m.get("devices",[]): print(("● " if d["online"] else "○ ")+d["name"]+" ["+d["id"]+"]")
                elif m.get("type")=="message": print(f"\n[{m['from_name']}] {m['text']}")
                elif m.get("type")=="error": print("\n"+m.get("message","Error"))
        task=asyncio.create_task(receive())
        try:
            while True:
                line=await asyncio.to_thread(input,"> ")
                if line=="/quit": break
                if line=="/users":
                    req=urllib.request.Request(cfg["server"]+"/api/chat/devices",headers={"Authorization":"Bearer "+cfg["device_token"]})
                    with urllib.request.urlopen(req,timeout=10) as r:
                        for d in json.load(r)["devices"]: print(("● " if d["online"] else "○ ")+d["name"]+" ["+d["id"]+"]")
                elif line.startswith("/to "): current=line[4:].strip(); print("Chat target set to",current)
                elif line.strip() and current:
                    await ws.send(json.dumps({"type":"message","to":current,"text":line}))
                elif line.strip(): print("Choose a recipient first: /to DEVICE_ID")
        finally:
            task.cancel()

def main():
    p=argparse.ArgumentParser(prog="cbridge-chat"); sub=p.add_subparsers(dest="cmd")
    q=sub.add_parser("pair"); q.add_argument("--server",required=True); q.add_argument("--name",required=True); q.add_argument("--password")
    sub.add_parser("connect")
    a=p.parse_args()
    if a.cmd=="pair": pair(a)
    else: asyncio.run(run())
if __name__=="__main__": main()

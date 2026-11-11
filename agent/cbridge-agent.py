#!/usr/bin/env python3
import argparse, asyncio, json, os, shutil, subprocess
import websockets

def read_clipboard():
    if shutil.which("wl-paste"):
        p=subprocess.run(["wl-paste","--no-newline"],capture_output=True,text=True,timeout=2)
        return p.stdout if p.returncode==0 else ""
    if shutil.which("xclip"):
        p=subprocess.run(["xclip","-selection","clipboard","-o"],capture_output=True,text=True,timeout=2)
        return p.stdout if p.returncode==0 else ""
    return None

def write_clipboard(value):
    if shutil.which("wl-copy"):
        subprocess.run(["wl-copy"],input=value,text=True,timeout=2,check=True)
    elif shutil.which("xclip"):
        subprocess.run(["xclip","-selection","clipboard"],input=value,text=True,timeout=2,check=True)
    else:
        raise RuntimeError("Install wl-clipboard or xclip")

async def run(server, token):
    uri=server.rstrip("/")+"/ws"
    if uri.startswith("http://"): uri="ws://"+uri[7:]
    if uri.startswith("https://"): uri="wss://"+uri[8:]
    last=None
    while True:
        try:
            async with websockets.connect(uri,max_size=200000) as ws:
                await ws.send(json.dumps({"token":token}))
                async def receive():
                    nonlocal last
                    async for raw in ws:
                        msg=json.loads(raw)
                        if msg.get("type")=="clipboard":
                            value=msg.get("text","")
                            if value!=last:
                                try: write_clipboard(value)
                                except Exception as exc: print("Clipboard write failed:",exc)
                                last=value
                async def send():
                    nonlocal last
                    while True:
                        value=await asyncio.to_thread(read_clipboard)
                        if value is not None and value!=last:
                            await ws.send(json.dumps({"type":"clipboard","text":value,"source":os.uname().nodename}))
                            last=value
                        await asyncio.sleep(1)
                tasks=[asyncio.create_task(receive()),asyncio.create_task(send())]
                done,pending=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
                for task in pending: task.cancel()
        except Exception as exc:
            print("Disconnected:",exc,"- retrying in 5 seconds")
            await asyncio.sleep(5)

if __name__=="__main__":
    parser=argparse.ArgumentParser(description="CanberraAI Chat Linux clipboard agent")
    parser.add_argument("--server",required=True,help="Server URL, e.g. ws://host:8765")
    parser.add_argument("--token",required=True)
    args=parser.parse_args()
    try: asyncio.run(run(args.server,args.token))
    except KeyboardInterrupt: pass

#!/usr/bin/env python3
"""Authorized Linux host telemetry agent. Metadata only: no packet payloads or keystrokes."""
import argparse, asyncio, ipaddress, json, os, platform, socket, subprocess, threading, time, urllib.request
from collections import deque
import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

SKIP_PARTS = ("/proc/", "/sys/", "/dev/", "/run/", "/var/cache/", "/var/log/journal/",
              "/var/lib/docker/", "/var/lib/containerd/", "/var/lib/cbridge/", "/var/lib/apt/", "/var/lib/dpkg/", "/var/lib/systemd/", "/var/lib/snapd/", "/var/lib/containers/", "/var/lib/kubelet/")
SYSTEM_ROOTS = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/opt", "/var")
PACKAGE_LOGS = ("/var/log/dpkg.log", "/var/log/apt/history.log")

def ip_scope(value):
    try:
        ip = ipaddress.ip_address(value.split("%")[0])
        if ip.is_loopback: return "LOOPBACK"
        if ip.is_private or ip.is_link_local: return "PRIVATE_OR_LAN"
        return "PUBLIC_INTERNET"
    except Exception: return "UNKNOWN"

def classify_path(path):
    p=os.path.abspath(path)
    if p.startswith(("/media/","/mnt/")): return "EXTERNAL_STORAGE"
    if p=="/home" or p.startswith("/home/"): return "USER_FILE"
    if p.startswith(("/tmp/","/var/tmp/")): return "TEMPORARY_FILE"
    if p.startswith("/var/lib/"): return "APPLICATION_DATA"
    if any(p==root or p.startswith(root+"/") for root in SYSTEM_ROOTS): return "SYSTEM_FILE"
    return "OTHER_FILE"

def send_batch(url,token,events):
    data=json.dumps({"events":events}).encode()
    req=urllib.request.Request(url.rstrip("/")+"/api/sentinel/events",data=data,
        headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(req,timeout=10) as response: response.read()

class FileEvents(FileSystemEventHandler):
    def __init__(self,emit):
        self.emit=emit; self.recent={}; self.lock=threading.Lock()
    def on_any_event(self,event):
        if event.is_directory or event.event_type not in ("created","modified","deleted","moved"):return
        paths=[getattr(event,"src_path",None)]
        if event.event_type=="moved":paths.append(getattr(event,"dest_path",None))
        now=time.time()
        for path in filter(None,paths):
            path=os.path.abspath(path)
            if any(x in path for x in SKIP_PARTS):continue
            key=(event.event_type,path)
            with self.lock:
                if now-self.recent.get(key,0)<3:continue
                self.recent[key]=now
            label={"created":"FILE_CREATED","modified":"FILE_MODIFIED","deleted":"FILE_DELETED","moved":"FILE_MOVED"}.get(event.event_type,"FILE_CHANGED")
            self.emit({"category":"FILESYSTEM","label":label,"severity":"info",
                "summary":f"{label.replace('_',' ').title()}: {path}",
                "details":{"path":path,"classification":classify_path(path),"operation":event.event_type}})

class Sentinel:
    def __init__(self,server,token,paths):
        self.server=server;self.token=token;self.host=socket.gethostname()
        self.events=deque(maxlen=2000);self.observer=Observer();self.paths=paths
        self.last_process={};self.process_baseline=False;self.last_connections=set();self.log_offsets={};self.last_heartbeat=0
    def emit(self,event):
        event.update({"ts":time.time(),"host":self.host});self.events.append(event)
    def start_watches(self):
        handler=FileEvents(self.emit)
        for path in self.paths:
            if os.path.isdir(path):
                try:self.observer.schedule(handler,path,recursive=True)
                except Exception as exc:print("Cannot watch",path,exc)
        self.observer.start()
    def scan_processes(self):
        current={}
        for p in psutil.process_iter(["pid","name","exe","username","ppid","create_time"]):
            try:
                info=p.info;pid=info["pid"];current[pid]=info
                if self.process_baseline and pid not in self.last_process:
                    parent=psutil.Process(info["ppid"]).name() if info.get("ppid") else None
                    self.emit({"category":"PROCESS","label":"PROCESS_STARTED","severity":"notice",
                        "summary":"Process started: "+str(info.get("name") or "unknown"),
                        "details":{"pid":pid,"name":info.get("name"),"executable":info.get("exe"),
                            "user":info.get("username"),"parent_pid":info.get("ppid"),"parent_name":parent}})
            except (psutil.NoSuchProcess,psutil.AccessDenied,psutil.ZombieProcess):pass
        self.last_process=current;self.process_baseline=True
    def scan_connections(self):
        current=set()
        try:conns=psutil.net_connections(kind="inet")
        except Exception:return
        listeners={}
        for item in conns:
            if item.status==psutil.CONN_LISTEN and item.laddr:
                listeners.setdefault(item.laddr.port,set()).add(item.laddr.ip)
        for c in conns:
            if not c.laddr or not c.raddr:continue
            lip,lport=c.laddr.ip,c.laddr.port;rip,rport=c.raddr.ip,c.raddr.port
            listener_ips=listeners.get(lport,set())
            direction="INBOUND" if any(addr in (lip,"0.0.0.0","::") for addr in listener_ips) else "OUTBOUND"
            key=(c.pid,lip,lport,rip,rport,c.status,direction);current.add(key)
            if key not in self.last_connections:
                try:
                    proc=psutil.Process(c.pid) if c.pid else None
                    pname=proc.name() if proc else None;exe=proc.exe() if proc else None
                except Exception:pname=exe=None
                protocol="TCP" if c.type==socket.SOCK_STREAM else "UDP"
                self.emit({"category":"NETWORK","label":"CONNECTION_"+direction,"severity":"notice",
                    "summary":f"{direction.title()} {protocol} {rip}:{rport}",
                    "details":{"direction":direction,"protocol":protocol,"local_ip":lip,"local_port":lport,
                        "remote_ip":rip,"remote_port":rport,"remote_scope":ip_scope(rip),
                        "state":c.status,"pid":c.pid,"process":pname,"executable":exe}})
        self.last_connections=current
    def scan_packages(self):
        for path in PACKAGE_LOGS:
            try:
                size=os.path.getsize(path)
                if path not in self.log_offsets:
                    self.log_offsets[path]=size
                    continue
                offset=self.log_offsets[path]
                if size<offset:offset=0
                with open(path,errors="replace") as f:f.seek(offset);lines=f.readlines();self.log_offsets[path]=f.tell()
                for line in lines[-100:]:
                    low=line.lower()
                    if any(x in low for x in (" install "," upgrade "," remove "," purge ","status installed")):
                        self.emit({"category":"INSTALLATION","label":"PACKAGE_CHANGE",
                            "severity":"warning" if "remove" in low or "purge" in low else "notice",
                            "summary":"Package manager activity: "+line.strip()[:300],
                            "details":{"log":path,"entry":line.strip()[:1000]}})
            except (OSError,PermissionError):pass
    async def run(self):
        self.start_watches()
        while True:
            self.scan_processes();self.scan_connections();self.scan_packages()
            now=time.time()
            if now-self.last_heartbeat>=60:
                self.emit({"category":"SYSTEM","label":"HOST_HEARTBEAT","severity":"info",
                    "summary":"Monitoring agent active","details":{"platform":platform.platform(),
                    "agent":"CanberraAI Sentinel","watched_paths":self.paths}})
                self.last_heartbeat=now
            batch=[]
            while self.events and len(batch)<100:batch.append(self.events.popleft())
            if batch:
                try:await asyncio.to_thread(send_batch,self.server,self.token,batch)
                except Exception as exc:
                    for item in reversed(batch):
                        if len(self.events)<self.events.maxlen:self.events.appendleft(item)
                    print("Upload failed:",exc)
            await asyncio.sleep(15)

def main():
    p=argparse.ArgumentParser(description="CanberraAI Sentinel authorized Linux telemetry agent")
    p.add_argument("--server",required=True,help="Base URL, e.g. https://sentinel.example.com")
    p.add_argument("--token",required=True)
    p.add_argument("--paths",default="/etc,/usr/local,/usr/bin,/usr/sbin,/usr/lib/systemd/system,/opt,/var/lib,/home,/media,/mnt")
    a=p.parse_args()
    agent=Sentinel(a.server,a.token,[x.strip() for x in a.paths.split(",") if x.strip()])
    try:asyncio.run(agent.run())
    except KeyboardInterrupt:pass
    finally:
        if agent.observer.is_alive():agent.observer.stop();agent.observer.join(timeout=3)
if __name__=="__main__":main()

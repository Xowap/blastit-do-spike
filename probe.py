"""
blastit DO App Platform spike.

Probes the platform primitives the blastit architecture depends on (see
ARCHITECTURE.md §11 in the blastit repo) and serves the report as JSON on $PORT.

Stdlib only. Every probe runs in a forked child so that a crash, a seccomp
filter or a uid drop never affects the parent, and each probe is bounded in
time.
"""

import ctypes
import ctypes.util
import errno
import json
import os
import platform
import resource
import signal
import socket
import struct
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]

PR_SET_PDEATHSIG = 1
PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4
PR_SET_SECCOMP = 22
PR_SET_CHILD_SUBREAPER = 36
PR_SET_NO_NEW_PRIVS = 38
SECCOMP_MODE_FILTER = 2
SYS_PIDFD_OPEN = 434

CAP_NAMES = [
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL",
    "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE", "NET_BIND_SERVICE",
    "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER",
    "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT",
    "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME",
    "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL",
    "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM",
    "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF", "CHECKPOINT_RESTORE",
]


def prctl(option, a2=0, a3=0, a4=0, a5=0):
    r = libc.prctl(option, a2, a3, a4, a5)
    if r == -1:
        e = ctypes.get_errno()
        raise OSError(e, f"prctl({option}): {os.strerror(e)}")
    return r


def read(path, limit=20000):
    try:
        with open(path) as f:
            return f.read(limit)
    except Exception as e:  # noqa: BLE001
        return f"<{type(e).__name__}: {e}>"


def status_fields(pid="self"):
    out = {}
    text = read(f"/proc/{pid}/status")
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k] = v.strip()
    return out


def decode_caps(hexstr):
    try:
        v = int(hexstr, 16)
    except (TypeError, ValueError):
        return hexstr
    return [n for i, n in enumerate(CAP_NAMES) if v >> i & 1] + [
        f"cap{i}" for i in range(len(CAP_NAMES), 64) if v >> i & 1
    ]


def caps_now():
    st = status_fields()
    return {
        k: decode_caps(st.get(k))
        for k in ("CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb")
    } | {
        "NoNewPrivs": st.get("NoNewPrivs"),
        "Seccomp": st.get("Seccomp"),
    }


def drop_to(uid):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)


def in_child(fn, uid=None, timeout=20.0):
    """Run fn() in a forked child (optionally as uid); return its JSON result."""
    r, w = os.pipe()
    t0 = time.monotonic()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            if uid is not None:
                drop_to(uid)
            res = {"ok": True, "result": fn()}
        except BaseException as e:  # noqa: BLE001
            res = {"ok": False, "error": f"{type(e).__name__}: {e}", "tb": traceback.format_exc()}
        data = json.dumps(res, default=str).encode()
        try:
            os.write(w, data)
        finally:
            os._exit(0)
    os.close(w)
    chunks = []
    deadline = time.monotonic() + timeout
    os.set_blocking(r, False)
    while True:
        try:
            c = os.read(r, 65536)
            if not c:
                break
            chunks.append(c)
        except BlockingIOError:
            if time.monotonic() > deadline:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                os.close(r)
                return {"ok": False, "error": "timeout"}
            time.sleep(0.01)
    os.close(r)
    _, status = os.waitpid(pid, 0)
    try:
        res = json.loads(b"".join(chunks) or b"null")
    except ValueError:
        res = {"ok": False, "error": "bad child output"}
    if res is None:
        res = {"ok": False, "error": f"child died, wait status {status}"}
    res["elapsed_ms"] = round((time.monotonic() - t0) * 1000, 1)
    return res


def probe(name, results):
    def deco(fn):
        try:
            results[name] = fn()
        except BaseException as e:  # noqa: BLE001
            results[name] = {"ok": False, "error": f"{type(e).__name__}: {e}", "tb": traceback.format_exc()}
        print(f"[probe] {name}: {json.dumps(results[name], default=str)[:1500]}", file=LOG, flush=True)
        return fn
    return deco


# --------------------------------------------------------------------------- #


def run_all():
    R = {}

    @probe("environment", R)
    def _():
        mem = {}
        for line in read("/proc/meminfo").splitlines()[:5]:
            k, v = line.split(":", 1)
            mem[k] = v.strip()
        return {
            "uname": platform.uname()._asdict(),
            "python": sys.version,
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(),
            "groups": os.getgroups(),
            "caps": caps_now(),
            "uid_map": read("/proc/self/uid_map"),
            "gid_map": read("/proc/self/gid_map"),
            "cpu_count": os.cpu_count(),
            "sched_affinity": len(os.sched_getaffinity(0)),
            "meminfo_head": mem,
            "cgroup": read("/proc/self/cgroup"),
            "cgroup_memory_max": read("/sys/fs/cgroup/memory.max"),
            "cgroup_memory_current": read("/sys/fs/cgroup/memory.current"),
            "cgroup_v1_limit": read("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
            "mounts": read("/proc/mounts"),
            "rlimits": {
                n: resource.getrlimit(getattr(resource, n))
                for n in ("RLIMIT_NPROC", "RLIMIT_NOFILE", "RLIMIT_AS", "RLIMIT_CORE", "RLIMIT_STACK")
            },
            "smaps_rollup_self": read("/proc/self/smaps_rollup"),
            "env_keys": sorted(os.environ),
            "port": os.environ.get("PORT"),
            "tmp_mode": oct(os.stat("/tmp").st_mode),
            "dev_shm": os.path.isdir("/dev/shm") and oct(os.stat("/dev/shm").st_mode),
            "interfaces": socket.if_nameindex(),
            "pid_max": read("/proc/sys/kernel/pid_max"),
            "threads_max": read("/proc/sys/kernel/threads-max"),
        }

    # S1 — can root drop to an arbitrary uid?
    @probe("S1_setuid", R)
    def _():
        def child():
            before = caps_now()
            drop_to(20000)
            return {
                "uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(),
                "groups": os.getgroups(), "caps_before": before["CapEff"],
                "caps_after": caps_now(),
                "setuid_back_to_0": _try(lambda: os.setuid(0)),
            }
        return in_child(child)

    # S4 — which uids are usable?
    @probe("S4_uid_range", R)
    def _():
        out = {}
        for uid in (1000, 20000, 21000, 65534, 65535, 65536, 100000, 1000000, 2**31 - 2, 2**32 - 2):
            out[str(uid)] = in_child(lambda u=uid: {"uid": os.getuid()}, uid=uid, timeout=5)
        return out

    # S2 — SO_PEERCRED returns the post-setuid uid (process and thread)
    @probe("S2_peercred", R)
    def _():
        d = "/tmp/blastit-spike-pg"
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o711)
        path = f"{d}/.s.PGSQL.5432"
        if os.path.exists(path):
            os.unlink(path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        os.chmod(path, 0o666)
        srv.listen(16)
        srv.settimeout(10)
        out = {}

        def client(use_thread):
            def connect():
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(path)
                s.sendall(b"x")
                s.recv(1)
                s.close()
            if use_thread:
                t = threading.Thread(target=connect)
                t.start()
                t.join()
            else:
                connect()
            return {"uid": os.getuid(), "pid": os.getpid()}

        for label, uid, thr in (("process_uid21000", 21000, False), ("thread_uid21001", 21001, True)):
            pid = os.fork()
            if pid == 0:
                try:
                    drop_to(uid)
                    client(thr)
                finally:
                    os._exit(0)
            try:
                conn, _ = srv.accept()
                cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                p, u, g = struct.unpack("3i", cred)
                conn.recv(1)
                conn.sendall(b"y")
                conn.close()
                out[label] = {"expected_uid": uid, "child_pid": pid, "peer_pid": p, "peer_uid": u, "peer_gid": g,
                              "match": u == uid}
            except Exception as e:  # noqa: BLE001
                out[label] = {"error": f"{type(e).__name__}: {e}"}
            os.waitpid(pid, 0)
        srv.close()
        os.unlink(path)

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        pid = os.fork()
        if pid == 0:
            a.close()
            drop_to(21002)
            b.sendall(b"x")
            os._exit(0)
        b.close()
        a.recv(1)
        p, u, g = struct.unpack("3i", a.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        out["socketpair_after_child_setuid"] = {
            "peer_uid": u, "note": "socketpair creds are fixed at creation (expect 0 on Linux)"}
        os.waitpid(pid, 0)
        a.close()
        return out

    # S3 — seccomp filter installed by the app is enforced
    @probe("S3_seccomp", R)
    def _():
        def child():
            install_socket_filter()
            res = {"status_seccomp": status_fields().get("Seccomp"),
                   "status_nnp": status_fields().get("NoNewPrivs")}
            res["af_unix"] = _try(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close() or "ok")
            res["af_inet"] = _try(lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).close() or "ok")
            res["af_inet6"] = _try(lambda: socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close() or "ok")
            res["enforced"] = res["af_unix"] == "ok" and "EPERM" in str(res["af_inet"])
            return res
        return in_child(child, uid=20010)

    # S5 — RLIMIT_NPROC semantics: per uid? threads counted?
    @probe("S5_rlimit_nproc", R)
    def _():
        def threads_until_fail(limit=200):
            ev = threading.Event()
            ts = []
            err = None
            try:
                for _ in range(limit):
                    t = threading.Thread(target=ev.wait)
                    t.start()
                    ts.append(t)
            except Exception as e:  # noqa: BLE001
                err = f"{type(e).__name__}: {e}"
            n = len(ts)
            ev.set()
            for t in ts:
                t.join()
            return n, err

        def alone():
            resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
            n, err = threads_until_fail()
            return {"threads_created_with_limit_16": n, "error": err}

        def with_sibling():
            # A sibling process of the same uid holds 8 threads; is it counted?
            r, w = os.pipe()
            r2, w2 = os.pipe()
            pid = os.fork()
            if pid == 0:
                ev = threading.Event()
                ts = [threading.Thread(target=ev.wait) for _ in range(8)]
                for t in ts:
                    t.start()
                os.write(w, b"1")
                os.read(r2, 1)
                ev.set()
                os._exit(0)
            os.read(r, 1)
            resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
            n, err = threads_until_fail()
            os.write(w2, b"1")
            os.waitpid(pid, 0)
            return {"threads_created_with_limit_16_and_sibling_holding_8": n, "error": err}

        def forks():
            resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
            pids, err = [], None
            try:
                for _ in range(100):
                    p = os.fork()
                    if p == 0:
                        time.sleep(30)
                        os._exit(0)
                    pids.append(p)
            except Exception as e:  # noqa: BLE001
                err = f"{type(e).__name__}: {e}"
            for p in pids:
                os.kill(p, signal.SIGKILL)
                os.waitpid(p, 0)
            return {"forks_with_limit_16": len(pids), "error": err}

        def no_limit():
            n, err = threads_until_fail(500)
            return {"threads_created_default_limit": n, "error": err}

        return {
            "alone": in_child(alone, uid=22000),
            "with_sibling": in_child(with_sibling, uid=22001),
            "forks": in_child(forks, uid=22002),
            "no_limit": in_child(no_limit, uid=22003),
        }

    # S6 — memory: preload, fork N children under N uids, observe
    @probe("S6_memory", R)
    def _():
        return memory_probe()

    @probe("ipc_primitives", R)
    def _():
        out = {}
        # SOCK_SEQPACKET socketpair + max message
        try:
            a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            sizes = {}
            for size in (64 << 10, 200 << 10, 1 << 20):
                sizes[size] = _try(lambda s=size: a.send(b"x" * s))
                if isinstance(sizes[size], int):
                    b.recv(size)
            out["seqpacket"] = {"ok": True, "send_sizes": sizes, "sndbuf": a.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)}
            a.close(); b.close()
        except Exception as e:  # noqa: BLE001
            out["seqpacket"] = {"ok": False, "error": str(e)}
        # SCM_RIGHTS across a uid boundary
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        pid = os.fork()
        if pid == 0:
            a.close()
            drop_to(20020)
            try:
                msg, fds, _, _ = socket.recv_fds(b, 16, 1)
                os.write(fds[0], b"hello-from-passed-fd")
                b.sendall(b"ok")
            except Exception as e:  # noqa: BLE001
                b.sendall(f"err {e}".encode())
            os._exit(0)
        b.close()
        pr, pw = os.pipe()
        socket.send_fds(a, [b"f"], [pw])
        os.close(pw)
        reply = a.recv(100)
        os.waitpid(pid, 0)
        out["scm_rights"] = {"reply": reply.decode(), "data": os.read(pr, 100).decode()}
        os.close(pr); a.close()
        # execve /proc/self/exe with a clean env
        import subprocess
        p = subprocess.run(["/proc/self/exe", "-c", "import os,sys; print(os.getpid(), len(os.environ), sys.executable)"],
                           env={"X": "1"}, capture_output=True, text=True, timeout=20)
        out["exec_proc_self_exe"] = {"rc": p.returncode, "out": p.stdout.strip(), "err": p.stderr[-300:]}
        out["pidfd_open"] = _syscall(SYS_PIDFD_OPEN, os.getpid(), 0)
        out["loopback_bind"] = _try(lambda: _bind("127.0.0.1"))
        out["any_bind"] = _try(lambda: _bind("0.0.0.0"))
        return out

    @probe("isolation", R)
    def _():
        out = {}
        # Victim: uid 20031, with a secret in its environ, sleeping.
        r, w = os.pipe()
        victim = os.fork()
        if victim == 0:
            drop_to(20031)
            os.write(w, b"1")
            os.execve(sys.executable, [sys.executable, "-c", "import time; time.sleep(60)"],
                      {"SECRET": "hunter2"})
        os.read(r, 1)
        time.sleep(0.3)

        def attacker():
            res = {}
            res["kill_other_uid"] = _try(lambda: os.kill(victim, 0) or "allowed")
            res["read_environ"] = _try(lambda: open(f"/proc/{victim}/environ", "rb").read()[:80])
            res["read_mem"] = _try(lambda: open(f"/proc/{victim}/mem", "rb").read(1))
            res["read_cmdline"] = _try(lambda: open(f"/proc/{victim}/cmdline", "rb").read()[:80])
            res["read_init_environ"] = _try(lambda: open("/proc/1/environ", "rb").read()[:80])
            libc.ptrace.restype = ctypes.c_long
            rr = libc.ptrace(16, victim, 0, 0)  # PTRACE_ATTACH
            res["ptrace_attach"] = "allowed" if rr == 0 else os.strerror(ctypes.get_errno())
            return res
        out["attacker_uid20030"] = in_child(attacker, uid=20030)
        os.kill(victim, signal.SIGKILL)
        os.waitpid(victim, 0)

        # CAP_CHOWN + private dir
        d = "/tmp/blastit-spike-priv"
        os.makedirs(d, exist_ok=True)
        out["chown_dir"] = _try(lambda: os.chown(d, 20040, 20040) or "ok")
        os.chmod(d, 0o700)
        out["owner_can_write"] = in_child(lambda: open(f"{d}/f", "w").write("x"), uid=20040)
        out["other_can_list"] = in_child(lambda: os.listdir(d), uid=20041)

        # PR_SET_DUMPABLE and PDEATHSIG
        out["set_dumpable_0"] = in_child(lambda: (prctl(PR_SET_DUMPABLE, 0), prctl(PR_GET_DUMPABLE))[1])
        out["pdeathsig"] = pdeathsig_probe()
        out["subreaper"] = _try(lambda: prctl(PR_SET_CHILD_SUBREAPER, 1) or "ok")
        return out

    R["summary"] = summarize(R)
    print("[summary] " + json.dumps(R["summary"]), file=LOG, flush=True)
    return R


def _try(fn):
    try:
        return fn()
    except OSError as e:
        return f"{errno.errorcode.get(e.errno, e.errno)}: {e.strerror}"
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"


def _syscall(nr, *args):
    r = libc.syscall(nr, *args)
    if r == -1:
        e = ctypes.get_errno()
        return f"{errno.errorcode.get(e, e)}: {os.strerror(e)}"
    os.close(r)
    return "ok"


def _bind(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return f"ok :{port}"


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def install_socket_filter():
    """socket(): allow AF_UNIX only, EPERM otherwise. Everything else allowed."""
    LD, JEQ, RET = 0x20, 0x15, 0x06
    prog = [
        (LD, 0, 0, 4),                 # arch
        (JEQ, 1, 0, 0xC000003E),       # x86_64?
        (RET, 0, 0, 0x80000000),       # KILL_PROCESS
        (LD, 0, 0, 0),                 # nr
        (JEQ, 0, 3, 41),               # socket?
        (LD, 0, 0, 16),                # args[0] (low 32 bits)
        (JEQ, 1, 0, 1),                # AF_UNIX?
        (RET, 0, 0, 0x00050000 | errno.EPERM),
        (RET, 0, 0, 0x7FFF0000),       # ALLOW
    ]
    arr = (SockFilter * len(prog))(*[SockFilter(*i) for i in prog])
    fprog = SockFprog(len(prog), arr)
    prctl(PR_SET_NO_NEW_PRIVS, 1)
    r = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.cast(ctypes.byref(fprog), ctypes.c_void_p).value, 0, 0)
    if r != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"seccomp: {os.strerror(e)}")


def pdeathsig_probe():
    prctl(PR_SET_CHILD_SUBREAPER, 1)
    r, w = os.pipe()
    mid = os.fork()
    if mid == 0:
        gc = os.fork()
        if gc == 0:
            prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
            os.write(w, str(os.getpid()).encode().ljust(16))
            time.sleep(30)
            os._exit(0)
        os.read(r, 0)
        time.sleep(0.5)
        os._exit(0)
    gpid = int(os.read(r, 16).strip())
    os.waitpid(mid, 0)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        p, st = os.waitpid(gpid, os.WNOHANG)
        if p:
            return {"grandchild_reaped_by_us": True, "signaled": os.WIFSIGNALED(st),
                    "signal": os.WTERMSIG(st) if os.WIFSIGNALED(st) else None}
        time.sleep(0.05)
    os.kill(gpid, signal.SIGKILL)
    os.waitpid(gpid, 0)
    return {"grandchild_reaped_by_us": True, "signaled": False, "note": "PDEATHSIG did not fire within 5s"}


def mem_snapshot():
    st = status_fields()
    return {
        "VmRSS": st.get("VmRSS"),
        "cgroup_current": read("/sys/fs/cgroup/memory.current").strip(),
        "MemAvailable": next((l.split(":")[1].strip() for l in read("/proc/meminfo").splitlines()
                              if l.startswith("MemAvailable")), None),
    }


def memory_probe(n_children=20, buf_mib=128, n_objects=200_000):
    before = mem_snapshot()
    buf = bytearray(buf_mib << 20)
    mv = memoryview(buf)
    for off in range(0, len(buf), 4096):
        mv[off] = 1
    objs = [f"object-{i}" for i in range(n_objects)]
    import gc
    gc.collect()
    gc.freeze()
    after_alloc = mem_snapshot()

    results = {}
    for mode in ("read_buffer_only", "iterate_python_objects"):
        pids, readys, releases, fork_ms = [], [], [], []
        for i in range(n_children):
            r, w = os.pipe()
            r2, w2 = os.pipe()
            t0 = time.monotonic()
            pid = os.fork()
            if pid == 0:
                os.close(r); os.close(w2)
                drop_to(30000 + i)
                total = buf.count(1)
                if mode == "iterate_python_objects":
                    total += sum(len(o) for o in objs)
                st = status_fields()
                rep = {"uid": os.getuid(), "VmRSS": st.get("VmRSS"), "total": total,
                       "smaps_rollup": " ".join(read("/proc/self/smaps_rollup").split()[:40])}
                os.write(w, json.dumps(rep).encode())
                os.close(w)
                os.read(r2, 1)
                os._exit(0)
            fork_ms.append((time.monotonic() - t0) * 1000)
            os.close(w); os.close(r2)
            pids.append(pid); readys.append(r); releases.append(w2)
        reports = []
        for r in readys:
            data = b""
            while True:
                c = os.read(r, 65536)
                if not c:
                    break
                data += c
            os.close(r)
            reports.append(json.loads(data))
        snap = mem_snapshot()
        for w in releases:
            os.write(w, b"1"); os.close(w)
        for p in pids:
            os.waitpid(p, 0)
        results[mode] = {
            "children": n_children,
            "fork_ms_avg": round(sum(fork_ms) / len(fork_ms), 2),
            "fork_ms_max": round(max(fork_ms), 2),
            "uids_ok": all(rep["uid"] == 30000 + i for i, rep in enumerate(reports)),
            "child_VmRSS_sample": [rep["VmRSS"] for rep in reports[:3]],
            "child_smaps_rollup_sample": reports[0]["smaps_rollup"],
            "snapshot_with_children_alive": snap,
            "after_release": mem_snapshot(),
        }
    gc.unfreeze()
    del objs, mv, buf
    return {"before": before, "after_alloc": after_alloc, "buf_mib": buf_mib,
            "n_objects": n_objects, "runs": results}


def summarize(R):
    def g(*path):
        cur = R
        for p in path:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(p)
        return cur

    s = {}
    s1 = g("S1_setuid", "result")
    s["S1_setuid"] = bool(s1 and s1.get("uid") == 20000)
    s["S1_caps_root"] = g("environment", "caps", "CapEff")
    s2 = g("S2_peercred") or {}
    s["S2_peercred"] = {k: v.get("match") for k, v in s2.items() if isinstance(v, dict) and "match" in v}
    s["S3_seccomp_enforced"] = g("S3_seccomp", "result", "enforced")
    s4 = g("S4_uid_range") or {}
    s["S4_uids_ok"] = [k for k, v in s4.items() if v.get("ok")]
    s["S4_uids_failed"] = {k: v.get("error") for k, v in s4.items() if not v.get("ok")}
    s["S5"] = {
        "alone": g("S5_rlimit_nproc", "alone", "result", "threads_created_with_limit_16"),
        "with_sibling_8": g("S5_rlimit_nproc", "with_sibling", "result", "threads_created_with_limit_16_and_sibling_holding_8"),
        "forks": g("S5_rlimit_nproc", "forks", "result", "forks_with_limit_16"),
        "no_limit": g("S5_rlimit_nproc", "no_limit", "result", "threads_created_default_limit"),
    }
    runs = g("S6_memory", "runs") or {}
    s["S6"] = {m: {"fork_ms_avg": v.get("fork_ms_avg"), "uids_ok": v.get("uids_ok"),
                   "cgroup_current": g("S6_memory", "runs", m, "snapshot_with_children_alive", "cgroup_current")}
               for m, v in runs.items()}
    s["pid1"] = g("environment", "pid") == 1
    s["kernel"] = g("environment", "uname", "release")
    return s


REPORT = {}
LOG = sys.stdout


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global REPORT
        if self.path == "/rerun":
            REPORT = run_all()
        body = json.dumps(REPORT.get("summary") if self.path in ("/", "/summary") else REPORT,
                          indent=2, default=str).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("[http] " + fmt % args, flush=True)


def reap(_sig, _frame):
    while True:
        try:
            p, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if not p:
            return


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        LOG = sys.stderr
        print(json.dumps(run_all(), indent=2, default=str))
        sys.exit(0)
    REPORT = run_all()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    port = int(os.environ.get("PORT", "8080"))
    print(f"[http] serving on 0.0.0.0:{port}", flush=True)
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()

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

    @probe("R2_peer_identity", R)
    def _():
        return peer_identity_probe()

    @probe("R2_socket_dac", R)
    def _():
        return socket_dac_probe()

    @probe("R2_proc_leaks", R)
    def _():
        return proc_leak_probe()

    @probe("R2_memory_scaling", R)
    def _():
        return memory_scaling_probe()

    @probe("R3_exec_barrier", R)
    def _():
        return exec_barrier_probe()

    @probe("R3_python_heap_cow", R)
    def _():
        return python_heap_cow_probe()

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


# --------------------------------------------------------------------------- #
# Round 2


SCM_CREDENTIALS = 2
SO_PASSCRED = 16


def _wait_path(path, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            raise TimeoutError(path)
        time.sleep(0.02)


def _parse_creds(ancdata):
    for level, typ, data in ancdata:
        if level == socket.SOL_SOCKET and typ == SCM_CREDENTIALS:
            p, u, g = struct.unpack("3i", data[:12])
            return {"pid": p, "uid": u, "gid": g}
    return None


def peer_identity_probe():
    """Which peer-identity mechanisms report the *connecting* process's uid?"""
    out = {}
    d = "/tmp/spike-peer"
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o777)
    path = f"{d}/s"
    if os.path.exists(path):
        os.unlink(path)

    # Client, uid 20051: waits for the listener created by uid 20050.
    cpid = os.fork()
    if cpid == 0:
        try:
            drop_to(20051)
            _wait_path(path)
            time.sleep(0.1)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(path)
            obs = {"client_uid": os.getuid(), "client_pid": os.getpid()}
            p, u, g = struct.unpack("3i", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            obs["client_sees_server"] = {"pid": p, "uid": u, "gid": g}
            s.sendall(b"plain")
            time.sleep(0.2)
            true = struct.pack("3i", os.getpid(), os.getuid(), os.getgid())
            obs["send_true_creds"] = _try(lambda: s.sendmsg([b"true!"], [(socket.SOL_SOCKET, SCM_CREDENTIALS, true)]))
            time.sleep(0.2)
            forged = struct.pack("3i", os.getpid(), 0, 0)
            obs["send_forged_uid0"] = _try(lambda: s.sendmsg([b"forge"], [(socket.SOL_SOCKET, SCM_CREDENTIALS, forged)]))
            time.sleep(0.2)
            s.sendall(json.dumps(obs).encode())
            s.close()
        finally:
            os._exit(0)

    def listener():
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, SO_PASSCRED, 1)
        srv.bind(path)
        os.chmod(path, 0o777)
        srv.listen(4)
        srv.settimeout(10)
        conn, _ = srv.accept()
        conn.setsockopt(socket.SOL_SOCKET, SO_PASSCRED, 1)
        res = {"listener_uid": os.getuid(), "listener_pid": os.getpid()}
        p, u, g = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        res["accepted_SO_PEERCRED"] = {"pid": p, "uid": u, "gid": g}
        msgs = []
        conn.settimeout(5)
        for _ in range(6):
            try:
                data, anc, _, _ = conn.recvmsg(65536, socket.CMSG_SPACE(12))
            except Exception as e:  # noqa: BLE001
                msgs.append({"error": str(e)})
                break
            if not data:
                break
            msgs.append({"data": data[:300].decode(errors="replace"), "creds": _parse_creds(anc)})
        res["messages"] = msgs
        srv.close()
        return res

    out["listener_uid20050_client_uid20051"] = in_child(listener, uid=20050)
    os.waitpid(cpid, 0)
    if os.path.exists(path):
        os.unlink(path)

    # Same, but root listener (what dbproxy-as-root or init would see), stream + seqpacket
    for typ_name, typ in (("stream", socket.SOCK_STREAM), ("seqpacket", socket.SOCK_SEQPACKET)):
        p2 = f"{d}/root-{typ_name}"
        if os.path.exists(p2):
            os.unlink(p2)
        srv = socket.socket(socket.AF_UNIX, typ)
        srv.setsockopt(socket.SOL_SOCKET, SO_PASSCRED, 1)
        srv.bind(p2)
        os.chmod(p2, 0o777)
        srv.listen(4)
        srv.settimeout(10)
        cpid = os.fork()
        if cpid == 0:
            try:
                drop_to(20052)
                s = socket.socket(socket.AF_UNIX, typ)
                s.connect(p2)
                s.send(b"hello")
                time.sleep(0.3)
            finally:
                os._exit(0)
        conn, _ = srv.accept()
        conn.setsockopt(socket.SOL_SOCKET, SO_PASSCRED, 1)
        p, u, g = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        conn.settimeout(5)
        data, anc, _, _ = conn.recvmsg(100, socket.CMSG_SPACE(12))
        out[f"root_listener_{typ_name}_client_uid20052"] = {
            "SO_PEERCRED": {"pid": p, "uid": u, "gid": g},
            "SO_PASSCRED_auto_creds": _parse_creds(anc),
            "client_pid": cpid,
        }
        conn.close(); srv.close()
        os.waitpid(cpid, 0)
        os.unlink(p2)
    return out


def socket_dac_probe():
    """Is file permission on a Unix socket enforced at connect()? Does /proc/self/cwd work as a socket dir?"""
    out = {}
    base = "/tmp/spike-dac"
    os.makedirs(base, exist_ok=True)
    os.chmod(base, 0o755)

    def serve_once(srv, n):
        got = []
        srv.settimeout(3)
        for _ in range(n):
            try:
                c, _ = srv.accept()
                c.sendall(b"k")
                c.close()
                got.append("accepted")
            except socket.timeout:
                got.append("timeout")
        return got

    def connect_child(path, uid, cwd=None):
        def fn():
            if cwd:
                os.chdir(cwd)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(path)
            r = s.recv(1)
            s.close()
            return f"connected ({r!r})"
        return in_child(fn, uid=uid, timeout=8)

    # E: socket owned by 20060, mode 0600
    path = f"{base}/s0600"
    if os.path.exists(path):
        os.unlink(path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chown(path, 20060, 20060)
    os.chmod(path, 0o600)
    srv.listen(8)
    th = threading.Thread(target=lambda: out.__setitem__("accepts_0600", serve_once(srv, 2)))
    th.start()
    out["owner_uid20060_connect"] = connect_child(path, 20060)
    out["other_uid20061_connect"] = connect_child(path, 20061)
    th.join()
    srv.close()
    os.unlink(path)

    # E2: socket in a 0700 dir owned by 20062
    d2 = f"{base}/d20062"
    os.makedirs(d2, exist_ok=True)
    path = f"{d2}/s"
    if os.path.exists(path):
        os.unlink(path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o666)
    os.chown(d2, 20062, 20062)
    os.chmod(d2, 0o700)
    srv.listen(8)
    th = threading.Thread(target=lambda: out.__setitem__("accepts_dir0700", serve_once(srv, 2)))
    th.start()
    out["dir_owner_uid20062_connect"] = connect_child(path, 20062)
    out["other_uid20063_connect_via_dir0700"] = connect_child(path, 20063)
    th.join()
    srv.close()

    # F: /proc/self/cwd as the socket directory (same string for every view)
    d3 = f"{base}/v20070"
    os.makedirs(d3, exist_ok=True)
    path = f"{d3}/.s.PGSQL.5432"
    if os.path.exists(path):
        os.unlink(path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chown(path, 20070, 20070)
    os.chmod(path, 0o600)
    os.chown(d3, 20070, 20070)
    os.chmod(d3, 0o700)
    srv.listen(8)
    th = threading.Thread(target=lambda: out.__setitem__("accepts_proc_self_cwd", serve_once(srv, 1)))
    th.start()
    out["proc_self_cwd_connect_uid20070"] = connect_child("/proc/self/cwd/.s.PGSQL.5432", 20070, cwd=d3)
    th.join()
    srv.close()
    # what does /proc/self/cwd resolve to for a uid that cannot read the dir of another?
    out["proc_self_cwd_readlink"] = in_child(lambda: (os.chdir(d3), os.readlink("/proc/self/cwd"))[1], uid=20070)
    return out


def proc_leak_probe():
    """What can a uid read about another uid's process under gVisor, with and without PR_SET_DUMPABLE(0)?"""
    out = {}
    for label, dumpable in (("normal", True), ("dumpable0", False)):
        r, w = os.pipe()
        victim = os.fork()
        if victim == 0:
            drop_to(20081)
            os.set_inheritable(w, True)
            code = ("import ctypes,os,time;"
                    + ("" if dumpable else "ctypes.CDLL(None).prctl(4,0,0,0,0);")
                    + "f=open('/etc/hostname');"
                    "os.write(%d,b'1');time.sleep(60)" % w)
            os.execve(sys.executable, [sys.executable, "-c", code], {"SECRET": "hunter2"})
        os.close(w)
        os.read(r, 1)
        os.close(r)
        time.sleep(0.2)

        def attacker(v=victim):
            res = {}
            for f in ("environ", "cmdline", "maps", "status", "stat", "io", "mem", "auxv", "stack", "syscall"):
                res[f] = _try(lambda f=f: open(f"/proc/{v}/{f}", "rb").read()[:120])
            res["fd_list"] = _try(lambda: os.listdir(f"/proc/{v}/fd"))
            res["fd3_readlink"] = _try(lambda: os.readlink(f"/proc/{v}/fd/3"))
            res["cwd_readlink"] = _try(lambda: os.readlink(f"/proc/{v}/cwd"))
            res["root_list"] = _try(lambda: os.listdir(f"/proc/{v}/root")[:5])
            res["status_uid_line"] = _try(lambda: [l for l in open(f"/proc/{v}/status").read().splitlines() if l.startswith("Uid")])
            res["proc_owner"] = _try(lambda: (os.stat(f"/proc/{v}").st_uid, os.stat(f"/proc/{v}/environ").st_uid,
                                              oct(os.stat(f"/proc/{v}/environ").st_mode)))
            return res
        out[label] = in_child(attacker, uid=20080)
        os.kill(victim, signal.SIGKILL)
        os.waitpid(victim, 0)

    # A forked (not exec'd) child inherits the parent's initial environ block:
    # what does /proc/<child>/environ show after the parent changed os.environ?
    os.environ["SPIKE_SET_AFTER_START"] = "yes"
    r, w = os.pipe()
    child = os.fork()
    if child == 0:
        drop_to(20082)
        os.close(r)
        os.write(w, b"1")
        time.sleep(30)
        os._exit(0)
    os.close(w)
    os.read(r, 1)
    os.close(r)
    env = _try(lambda: open(f"/proc/{child}/environ", "rb").read())
    out["forked_child_environ_shows_runtime_changes"] = isinstance(env, bytes) and b"SPIKE_SET_AFTER_START" in env
    out["forked_child_environ_head"] = env[:200] if isinstance(env, bytes) else env
    os.kill(child, signal.SIGKILL)
    os.waitpid(child, 0)
    del os.environ["SPIKE_SET_AFTER_START"]
    return out


def memavail_kb():
    for l in read("/proc/meminfo").splitlines():
        if l.startswith("MemAvailable"):
            return int(l.split()[1])
    return None


def cg1(name):
    return read(f"/sys/fs/cgroup/memory/{name}").strip()


def memory_scaling_probe(n_children=10):
    """Per-child cost as a function of the parent's resident size."""
    out = {"cgroup_v1": {k: cg1(k) for k in ("memory.limit_in_bytes", "memory.usage_in_bytes",
                                                "memory.max_usage_in_bytes")},
           "cgroup_v1_stat_head": cg1("memory.stat")[:600]}
    import gc
    for mib in (0, 64, 256):
        gc.collect()
        time.sleep(1)
        base = memavail_kb()
        buf = bytearray(mib << 20) if mib else bytearray(1)
        mv = memoryview(buf)
        for off in range(0, len(buf), 4096):
            mv[off] = 1
        after_alloc = memavail_kb()
        pids, releases, fork_ms, avail_steps = [], [], [], []
        for i in range(n_children):
            r, w = os.pipe()
            r2, w2 = os.pipe()
            t0 = time.monotonic()
            pid = os.fork()
            if pid == 0:
                os.close(r); os.close(w2)
                drop_to(31000 + i)
                buf.count(1)
                os.write(w, b"1")
                os.read(r2, 1)
                os._exit(0)
            fork_ms.append(round((time.monotonic() - t0) * 1000, 1))
            os.close(w); os.close(r2)
            os.read(r, 1)
            os.close(r)
            pids.append(pid); releases.append(w2)
            avail_steps.append(memavail_kb())
        usage_with_children = cg1("memory.usage_in_bytes")
        for w in releases:
            os.write(w, b"1"); os.close(w)
        for p in pids:
            os.waitpid(p, 0)
        time.sleep(2)
        after_release = memavail_kb()
        del mv, buf
        gc.collect()
        time.sleep(2)
        after_free = memavail_kb()
        per_child = [(avail_steps[i - 1] if i else after_alloc) - avail_steps[i] for i in range(n_children)]
        out[f"parent_plus_{mib}MiB"] = {
            "memavail_kb": {"base": base, "after_alloc": after_alloc, "with_children": avail_steps[-1],
                            "after_release_2s": after_release, "after_free_2s": after_free},
            "alloc_cost_kb": base - after_alloc,
            "per_child_kb": per_child,
            "per_child_avg_kb": round(sum(per_child) / n_children),
            "fork_ms": fork_ms,
            "cgroup_usage_with_children": usage_with_children,
            "parent_VmRSS": status_fields().get("VmRSS"),
        }
    return out


def exec_barrier_probe():
    """Does re-exec'ing with a clean env clear what other uids see in /proc/<pid>/environ?"""
    out = {}
    r, w = os.pipe()
    victim = os.fork()
    if victim == 0:
        os.close(r)
        drop_to(20091)
        os.set_inheritable(w, True)
        # stage 0 has SECRET; it signals, waits 1s, then execs itself with a clean env
        stage1 = "import os,time;os.write(%d,b'2');time.sleep(60)" % w
        stage0 = ("import os,sys,time;os.write(%d,b'1');time.sleep(1.0);"
                  "os.execve(sys.executable,[sys.executable,'-c',%r],{'STAGE':'1'})" % (w, stage1))
        os.execve(sys.executable, [sys.executable, "-c", stage0], {"SECRET": "hunter2", "STAGE": "0"})
    os.close(w)
    os.read(r, 1)
    out["before_exec"] = in_child(lambda: open(f"/proc/{victim}/environ", "rb").read(), uid=20090)
    os.read(r, 1)
    time.sleep(0.2)
    out["after_exec"] = in_child(lambda: open(f"/proc/{victim}/environ", "rb").read(), uid=20090)
    out["pid_unchanged"] = True
    os.kill(victim, signal.SIGKILL)
    os.waitpid(victim, 0)
    os.close(r)
    out["barrier_works"] = ("hunter2" in str(out["before_exec"].get("result"))
                            and "hunter2" not in str(out["after_exec"].get("result")))
    return out


def python_heap_cow_probe(n_objects=250_000, n_children=5):
    """Cost per child of touching a fraction of a preloaded Python heap (cgroup v1 usage)."""
    import gc
    import random

    def usage():
        v = cg1("memory.usage_in_bytes")
        if v.isdigit():
            return int(v)
        v = read("/sys/fs/cgroup/memory.current").strip()
        return int(v) if v.isdigit() else None

    gc.collect()
    u0 = usage()
    objs = [{"k": i, "v": f"value-{i}"} for i in range(n_objects)]
    gc.collect()
    gc.freeze()
    u1 = usage()
    out = {"heap_cost_mib": round((u1 - u0) / 2**20, 1) if u0 and u1 else None, "runs": {}}
    rng = random.Random(42)
    plans = {
        "touch_none": [],
        "touch_0.1pct_random": rng.sample(range(n_objects), n_objects // 1000),
        "touch_1pct_random": rng.sample(range(n_objects), n_objects // 100),
        "touch_10pct_contiguous": list(range(n_objects // 10)),
        "touch_100pct": list(range(n_objects)),
    }
    for name, idx in plans.items():
        time.sleep(1)
        base = usage()
        pids, releases = [], []
        for i in range(n_children):
            r, w = os.pipe()
            r2, w2 = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(r); os.close(w2)
                drop_to(32000 + i)
                acc = 0
                for j in idx:
                    acc += objs[j]["k"]   # refcount writes on the dict and the int
                os.write(w, b"1")
                os.read(r2, 1)
                os._exit(0)
            os.close(w); os.close(r2)
            os.read(r, 1); os.close(r)
            pids.append(pid); releases.append(w2)
        with_children = usage()
        for w in releases:
            os.write(w, b"1"); os.close(w)
        for p in pids:
            os.waitpid(p, 0)
        out["runs"][name] = {
            "objects_touched": len(idx),
            "per_child_mib": round((with_children - base) / n_children / 2**20, 2) if base and with_children else None,
        }
    gc.unfreeze()
    del objs
    gc.collect()
    return out


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
    pi = g("R2_peer_identity") or {}
    s["R2_peer_identity"] = {
        k: {kk: (vv.get("uid") if isinstance(vv, dict) else vv) for kk, vv in v.items()
            if kk in ("SO_PEERCRED", "SO_PASSCRED_auto_creds")}
        for k, v in pi.items() if k.startswith("root_listener")
    }
    sd = g("R2_socket_dac") or {}
    s["R2_socket_dac"] = {k: (v.get("result") or v.get("error")) for k, v in sd.items()
                          if isinstance(v, dict) and k.endswith("connect") or k.endswith("connect_uid20070")
                          or k.endswith("via_dir0700")}
    pl = g("R2_proc_leaks") or {}
    s["R2_environ_readable_cross_uid"] = {
        k: str(g("R2_proc_leaks", k, "result", "environ"))[:60] for k in ("normal", "dumpable0")}
    s["R2_forked_child_environ_shows_runtime_changes"] = pl.get("forked_child_environ_shows_runtime_changes")
    ms = g("R2_memory_scaling") or {}
    s["R2_memory_per_child_kb"] = {k: v.get("per_child_avg_kb") for k, v in ms.items() if k.startswith("parent_")}
    s["R2_fork_ms"] = {k: v.get("fork_ms") for k, v in ms.items() if k.startswith("parent_")}
    s["R3_exec_barrier_works"] = g("R3_exec_barrier", "barrier_works")
    s["R3_python_heap_cow"] = g("R3_python_heap_cow")
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

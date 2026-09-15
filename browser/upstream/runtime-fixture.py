#!/usr/bin/env python3
"""Disposable real Tor/KPS network for the browser/native runtime contract.

Run only on a CI worker with the pinned Chutney source and isolated tool deps.
No host service or public directory authority participates in this fixture.
"""
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

CHUTNEY_REVISION = "6cc158868d722e652975cb4efd5b278d95ff2fbb"
source = Path(os.environ["CHUTNEY_SOURCE"]).resolve()
sys.path.insert(0, str(source / "lib"))
from chutney import TorNet
from chutney.TorNet import NodeConfig, NetworkConfig


def stop_child(child):
    if child is not None and child.poll() is None:
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()


def stop_signal(signum, _frame):
    raise KeyboardInterrupt(f"fixture interrupted by signal {signum}")


def save_tail(path, destination, limit):
    if path.is_file():
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - limit))
            destination.write_bytes(stream.read(limit))


def save_node_diagnostics(network, artifact, phase):
    # These fields describe only disposable process/listener configuration.
    # Never copy key directories, full torrc files or control authentication.
    safe_options = {"testingtornetwork", "datadirectory", "connlimit", "nickname",
                    "addressdisableipv6", "sandbox", "usemicrodescriptors",
                    "__owningcontrollerprocess", "socksport", "dnsport",
                    "controlport", "controlsocket", "runasdaemon", "address",
                    "orport", "dirport"}
    entries = []
    for node in network.nodes:
        entry = {"node": node.nick, "directory": str(node.dir),
                 "directoryExists": node.dir.is_dir(), "phase": phase}
        try:
            entry["running"] = node._controller.isRunning()
            pidfile = Path(node.pidfile)
            entry["pidFileExists"] = pidfile.is_file()
            if pidfile.is_file():
                with pidfile.open("rb") as stream:
                    pid = stream.read(128).strip()
                entry["pid"] = int(pid) if pid.isdigit() and len(pid) <= 10 else None
            torrc = node.torrc_path
            entry["torrcExists"] = torrc.is_file()
            if torrc.is_file():
                with torrc.open("rb") as stream:
                    lines = stream.read(65536).decode("utf-8", errors="replace").splitlines()
                entry["startupOptions"] = [line.strip() for line in lines
                    if line.split() and line.split()[0].lower() in safe_options]
            entry["filesPresent"] = [name for name in ["tor.stdout", "tor.stderr",
                "notice.log", "info.log", "cached-consensus", "cached-microdesc-consensus",
                "cached-descriptors", "cached-descriptors.new", "cached-microdescs",
                "cached-microdescs.new"] if (node.dir / name).is_file()]
            for name in ["tor.stdout", "tor.stderr", "notice.log", "info.log"]:
                save_tail(node.dir / name, artifact / f"{node.nick}-{name}", 4096)
        except OSError as error:
            entry["diagnosticError"] = type(error).__name__
        entries.append(entry)
    (artifact / f"node-status-{phase}.json").write_text(json.dumps(entries, indent=2) + "\n")


signal.signal(signal.SIGTERM, stop_signal)
signal.signal(signal.SIGINT, stop_signal)
root = Path(__file__).resolve().parents[2]
artifact = Path(os.environ["TOR_RUNTIME_ARTIFACT"]).resolve()
artifact.mkdir(parents=True, exist_ok=True)
os.environ["CHUTNEY_TOR"] = os.environ["TOR_BIN"]
os.environ["CHUTNEY_TOR_GENCERT"] = os.environ["TOR_GENCERT_BIN"]
for executable in [os.environ["TOR_BIN"], os.environ["TOR_GENCERT_BIN"],
                   os.environ["TOR_GATEWAY_BIN"], os.environ["TOR_NATIVE_PEER_BIN"]]:
    if not Path(executable).is_file():
        raise RuntimeError("missing isolated fixture executable")

with tempfile.TemporaryDirectory(prefix="cmsg-browser-tor-fixture-") as temporary:
    temporary = Path(temporary)
    # Exits are needed for a representative consensus, but this fixture never
    # requests an exit stream. Keep any resolver probing on loopback too.
    resolver = temporary / "resolv.conf"
    resolver.write_text("nameserver 127.0.0.1\n")
    network = TorNet.Network(NetworkConfig(tor_bin=os.environ["TOR_BIN"]))
    base = NodeConfig(controlling_pid=os.getpid(), connlimit=256, disableipv6=True,
                      ip="127.0.0.1", ipv6_addr=None,
                      launcher_backend=TorNet.LauncherBackend.LOCAL,
                      poll_launch_time=0.1,
                      sandbox=False, dns_conf=str(resolver), enable_dnsport=False,
                      extra_raw_torrc="ServerDNSDetectHijacking 0\n")
    authority = dataclasses.replace(base, tag="a", authority=True, relay=True)
    relay = dataclasses.replace(base, tag="r", relay=True)
    exit_relay = dataclasses.replace(base, tag="e", relay=True, exit=True)
    client = dataclasses.replace(base, tag="c", client=True)
    network.addNodes(authority.getN(4) + relay.getN(20) + exit_relay.getN(2) + client.getN(1))
    # Tor's outbound connections must not consume another node's listener port
    # during sequential startup. Select outside the worker's ephemeral range;
    # read kernel settings only and keep every reservation until launch.
    ephemeral = [int(value) for value in
        Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()]
    if len(ephemeral) != 2 or not 1 <= ephemeral[0] <= ephemeral[1] <= 65535:
        raise RuntimeError("invalid worker ephemeral port range")
    unprivileged = max(1024, int(Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text()))
    if not 1024 <= unprivileged <= 65535:
        raise RuntimeError("invalid worker unprivileged port range")
    intervals = [(unprivileged, ephemeral[0] - 1),
                 (max(unprivileged, ephemeral[1] + 1), 65535)]
    slots = [(low, high - low - 30) for low, high in intervals if high - low + 1 >= 32]
    available_starts = sum(count for _, count in slots)
    if available_starts == 0:
        raise RuntimeError("no unprivileged Tor listener interval outside ephemeral ports")
    reservations = []
    allocated_ports = {}
    for field in ["orport_base", "dirport_base", "controlport_base", "socksport_base",
                  "extorport_base", "ptport_base", "dnsport_base"]:
        for attempt in range(100):
            choice = secrets.randbelow(available_starts)
            for low, count in slots:
                if choice < count:
                    first = low + choice
                    break
                choice -= count
            group = []
            try:
                for port in range(first, first + 32):
                    reserved = socket.socket()
                    reserved.bind(("127.0.0.1", port))
                    group.append(reserved)
            except OSError:
                reserved.close()
                for reserved in group:
                    reserved.close()
                continue
            reservations.extend(group)
            setattr(network, field, first)
            allocated_ports[field] = [first, first + 31]
            break
        else:
            raise RuntimeError("cannot reserve isolated Tor ports outside ephemeral range")
    (artifact / "listener-ports.json").write_text(json.dumps({
        "synthetic": True, "ephemeral": ephemeral, "unprivilegedStart": unprivileged,
        "reservedBlocks": allocated_ports,
    }, indent=2) + "\n")
    gateway = None
    driver = None
    gateway_log = temporary / "gateway.log"
    log_handle = None
    try:
        network.init(data_dir=temporary / "tor")
        network.configure(config_phase=1)
        for reserved in reservations:
            reserved.close()
        network.start(launch_phase=1)
        save_node_diagnostics(network, artifact, "started")
        network.wait_for_bootstrap(launch_phase=1, limit_secs=360)
        nodes = list(network.nodes)
        authorities = []
        for node in nodes[:4]:
            certificate = (node.dir / "keys/authority_certificate").read_text()
            match = re.search(r"(?m)^fingerprint ([A-Fa-f0-9]{40})$", certificate)
            if not match:
                raise RuntimeError("fixture authority certificate missing identity")
            authorities.append(match[1])
        fallbacks = [{"rsa_identity": node.fingerprint.unwrap(),
                      "ed_identity": node.fingerprint_ed25519.unwrap(),
                      "orports": [f"127.0.0.1:{node.orport}"]} for node in nodes[:4]]
        consensus = nodes[-1].dir / "cached-microdesc-consensus"
        if not consensus.is_file():
            raise RuntimeError("fixture has no signed microdescriptor consensus")
        # C Tor's TestingTorNetwork mode derives the onion-directory time period
        # from the voting interval without publishing that override in params.
        # Use the exact pinned Chutney generator's Arti override, not the public
        # network default or an independently chosen test value.
        from chutney.arti.config import tor_config
        net_overrides = tor_config(network)["override_net_params"]
        if set(net_overrides) != {"hsdir_interval"} or type(net_overrides["hsdir_interval"]) is not int \
                or not 5 <= net_overrides["hsdir_interval"] <= 14400:
            raise RuntimeError("unsupported Chutney onion-directory interval derivation")
        if consensus.stat().st_size > 2 * 1024 * 1024:
            raise RuntimeError("synthetic consensus exceeds artifact bound")
        consensus_bytes = consensus.read_bytes()
        consensus_lines = consensus_bytes.decode("ascii").splitlines()
        hsdir_relays = sum(line.startswith("s ") and "HSDir" in line.split() for line in consensus_lines)
        if hsdir_relays == 0:
            raise RuntimeError("synthetic consensus has no onion directories")
        (artifact / "consensus-microdesc-start.txt").write_bytes(consensus_bytes)
        (artifact / "fixture-provenance.json").write_text(json.dumps({
            "chutneyRevision": CHUTNEY_REVISION, "authorities": 4, "guardRelays": 20,
            "exitRelays": 2, "nativeClients": 1, "vanguards": "full", "synthetic": True,
            "torVersion": subprocess.check_output([os.environ["TOR_BIN"], "--version"], text=True).strip(),
            "artiNetOverrides": net_overrides,
            "netOverrideSource": "pinned chutney.arti.config.tor_config(network)",
            "votingIntervalSeconds": network.v3_auth_voting_interval_seconds,
            "hsdirFormula": "12 rounds * 2 phases * votingIntervalSeconds / 60 minutes",
            "consensusSha256": hashlib.sha256(consensus_bytes).hexdigest(),
            "hsdirRelayCount": hsdir_relays,
            "consensusTiming": [line for line in consensus_lines if line.startswith((
                "valid-after ", "fresh-until ", "valid-until ", "voting-delay ", "params "))],
            "sharedRandomCurrentPresent": any(line.startswith("shared-rand-current-value ") for line in consensus_lines),
            "sharedRandomPreviousPresent": any(line.startswith("shared-rand-previous-value ") for line in consensus_lines),
        }, indent=2) + "\n")
        gateway_data = temporary / "gateway"
        gateway_data.mkdir()
        (gateway_data / "consensus-microdesc.txt").write_bytes(consensus_bytes)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", 0))
            gateway_port = udp.getsockname()[1]
        config = {"data_dir": str(gateway_data), "kps_port": gateway_port,
                  "kps_key_file": str(temporary / "synthetic-kps.key"), "keccak_dir": "",
                  "advertised_addresses": ["127.0.0.1"], "tunnel_max": 128,
                  "tunnel_per_ip": 128, "tunnel_idle_timeout": 300, "tunnel_max_lifetime": 1200}
        config_path = temporary / "gateway.json"
        config_path.write_text(json.dumps(config))
        log_handle = gateway_log.open("w")
        gateway = subprocess.Popen([os.environ["TOR_GATEWAY_BIN"], "--config", str(config_path), "run", "--no-sync"],
            env={**os.environ, "TOR_JS_GATEWAY_ALLOW_LOCAL_TARGETS": "1", "RUST_LOG": "info", "NO_COLOR": "1"},
            stdout=log_handle, stderr=subprocess.STDOUT, start_new_session=True)
        gateway_address = None
        for _ in range(300):
            if gateway.poll() is not None:
                raise RuntimeError("fixture gateway exited")
            match = re.search(r"127\.0\.0\.1:" + str(gateway_port) + r":[A-Za-z0-9_=-]+", gateway_log.read_text())
            if match:
                gateway_address = match[0]
                break
            time.sleep(0.1)
        if gateway_address is None:
            raise RuntimeError("fixture gateway address not available")
        fixture = {"testOnly": True, "gateway": gateway_address, "arti": {
            "tor_network": {"authorities": {"v3idents": authorities, "uploads": [], "downloads": [], "votes": []},
                            "fallback_caches": fallbacks},
            "path_rules": {"ipv4_subnet_family_prefix": 33, "ipv6_subnet_family_prefix": 129},
            "override_net_params": net_overrides, "vanguards": {"mode": "full"}}}
        fixture_path = temporary / "fixture.json"
        fixture_path.write_text(json.dumps(fixture))
        socks_ip, socks_port = next(iter(nodes[-1].socksport_endpoints()))
        environment = {**os.environ, "TOR_FIXTURE_JSON": str(fixture_path),
                       "TOR_NATIVE_SOCKS": f"{socks_ip}:{socks_port}",
                       "BROWSER_EVIDENCE": str(artifact / "browser-tor-runtime.json")}
        driver = subprocess.Popen(["node", str(root / "browser/upstream/runtime-driver.mjs")],
            cwd=root, env=environment, start_new_session=True)
        result = driver.wait(timeout=1000)
        if result != 0:
            raise RuntimeError("real browser Tor contract failed")
    finally:
        stop_child(driver)
        stop_child(gateway)
        if log_handle is not None:
            log_handle.close()
        try:
            save_tail(gateway_log, artifact / "gateway-synthetic.log", 65536)
            save_node_diagnostics(network, artifact, "final")
        finally:
            for reserved in reservations:
                reserved.close()
            network.stop()

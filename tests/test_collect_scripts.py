"""Tests for the collection wrappers in scripts/collect/ (ADR-021 decision 4).

The transports (ssh, kubectl, aws) are replaced by stub executables on PATH that run the real
collector locally, so the tests exercise the wrappers end to end: distribution of the collector,
classification of each target (succeeded / failed / unreachable), the collection manifest, and that
the audit reads the manifest as the pool's expected node count.
"""

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from triage_agent.chain.engine import build_pool_coverage, load_node_telemetries_with_report
from triage_agent.chain.models import EnvironmentDefinition, NodePoolDefinition

REPO = Path(__file__).resolve().parents[1]
COLLECT = REPO / "scripts" / "collect"

# Every simulated host runs the real collector on this machine; a per-host salt makes node ids differ.
SSH_STUB = r'''#!/usr/bin/env python3
import os, subprocess, sys
args = sys.argv[1:]
# skip ssh options: -o X
i = 0
while i < len(args) and args[i].startswith("-"):
    i += 2 if args[i] in ("-o", "-i", "-p", "-l") else 1
host, remote = args[i], args[i + 1]
if host.startswith("down"):
    sys.stderr.write("ssh: connect to host %s: Connection timed out\n" % host)
    sys.exit(255)
if host.startswith("broken"):
    sys.stdout.write("not json\n")
    sys.exit(0)
env = dict(os.environ, TRIAGE_NODE_ID_SALT="salt-" + host)
sys.exit(subprocess.call(["sh", "-c", remote], stdin=sys.stdin, env=env))
'''

KUBECTL_STUB = r'''#!/usr/bin/env python3
import os, subprocess, sys
args = sys.argv[1:]
log = os.environ["STUB_LOG"]
with open(log, "a") as f:
    f.write(" ".join(args) + "\n")
if args[:2] == ["get", "nodes"]:
    sys.stdout.write("node-a\tTrue\nnode-b\tTrue\nnode-c\tFalse\n")
    sys.exit(0)
if args and args[0] == "debug":
    node = args[1].split("/", 1)[1]
    sys.stderr.write("Creating debugging pod node-debugger-%s-xyz with container debugger on node %s.\n" % (node, node))
    inner = args[args.index("-c") + 1]
    env = dict(os.environ, TRIAGE_NODE_ID_SALT="salt-" + node)
    if node == "node-b":
        sys.exit(1)
    sys.exit(subprocess.call(["sh", "-c", inner], stdin=sys.stdin, env=env))
if args and args[0] == "delete":
    sys.exit(0)
sys.exit(2)
'''

AWS_STUB = r'''#!/usr/bin/env python3
import json, os, subprocess, sys
args = sys.argv[1:]
state = os.environ["STUB_STATE"]
def opt(name):
    return args[args.index(name) + 1] if name in args else None
if args[:2] == ["ec2", "describe-instances"]:
    print("i-001\ti-002\ti-003\ti-004")
elif args[:2] == ["ssm", "describe-instance-information"]:
    print("i-001\ti-002\ti-004")          # i-003 has no SSM agent online
elif args[:2] == ["ssm", "send-command"]:
    ids = args[args.index("--instance-ids") + 1: args.index("--parameters")]
    params = json.load(open(opt("--parameters")[len("file://"):]))
    with open(os.path.join(state, "cmd.json"), "w") as f:
        json.dump({"ids": ids, "command": params["commands"][0]}, f)
    print("cmd-1")
elif args[:2] == ["ssm", "list-command-invocations"]:
    cmd = json.load(open(os.path.join(state, "cmd.json")))
    for iid in cmd["ids"]:
        print("%s\t%s" % (iid, "Failed" if iid == "i-004" else "Success"))
elif args[:2] == ["ssm", "get-command-invocation"]:
    cmd = json.load(open(os.path.join(state, "cmd.json")))
    iid = opt("--instance-id")
    env = dict(os.environ, TRIAGE_NODE_ID_SALT="salt-" + iid)
    sys.stdout.write(subprocess.run(["sh", "-c", cmd["command"]], env=env, capture_output=True, text=True).stdout)
else:
    sys.exit(2)
'''


def _install_stub(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class CollectScriptTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.out = self.root / "telemetry"
        self.env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}")
        self.env.pop("TRIAGE_NODE_ID_SALT", None)

    def tearDown(self):
        self._tmp.cleanup()

    def run_script(self, name, *args):
        return subprocess.run(
            ["sh", str(COLLECT / name), *args, "-o", str(self.out)],
            env=self.env, capture_output=True, text=True, timeout=120,
        )

    def manifest(self, pool):
        return json.loads((self.out / pool / "collection_manifest.json").read_text(encoding="utf-8"))

    def node_files(self, pool):
        return sorted(p.name for p in (self.out / pool).glob("node-*.json"))


class TestCollectViaSsh(CollectScriptTestCase):
    def setUp(self):
        super().setUp()
        _install_stub(self.bin, "ssh", SSH_STUB)
        self.hosts = self.root / "hosts.txt"
        self.hosts.write_text("# dmz pool\nweb-01\nweb-02\n\ndown-03\nbroken-04\n", encoding="utf-8")

    def test_manifest_classifies_every_host(self):
        proc = self.run_script("collect_via_ssh.sh", "-p", "pool-dmz", "-H", str(self.hosts))
        self.assertEqual(proc.returncode, 2, proc.stderr)
        m = self.manifest("pool-dmz")
        self.assertEqual(m["kind"], "collection_manifest")
        self.assertEqual(m["method"], "ssh")
        self.assertEqual(m["targets"], ["web-01", "web-02", "down-03", "broken-04"])
        self.assertEqual(m["succeeded"], ["web-01", "web-02"])
        self.assertEqual(m["unreachable"], ["down-03"])
        self.assertEqual(m["failed"], ["broken-04"])
        # File names never contain host names.
        self.assertEqual(self.node_files("pool-dmz"), ["node-001.json", "node-002.json"])

    def test_audit_treats_partial_collection_as_incomplete(self):
        self.run_script("collect_via_ssh.sh", "-p", "pool-dmz", "-H", str(self.hosts))
        telemetries, issues = load_node_telemetries_with_report(str(self.out))
        self.assertEqual(telemetries["pool-dmz"].observed_nodes_count, 2)
        env = EnvironmentDefinition(
            environment_name="t",
            node_pools=[NodePoolDefinition(pool_id="pool-dmz", os_distribution="ubuntu", nodes_count=10)],
        )
        cov = build_pool_coverage(env, telemetries)["pool-dmz"]
        # The manifest (4 targets) wins over environments.yaml (10).
        self.assertEqual((cov.observed_nodes, cov.expected_nodes, cov.expected_source), (2, 4, "manifest"))
        self.assertTrue(cov.is_known_incomplete)
        self.assertTrue(any("届かなかった" in i.message for i in issues))

    def test_rerun_replaces_previous_results(self):
        self.run_script("collect_via_ssh.sh", "-p", "pool-dmz", "-H", str(self.hosts))
        self.hosts.write_text("web-01\n", encoding="utf-8")
        proc = self.run_script("collect_via_ssh.sh", "-p", "pool-dmz", "-H", str(self.hosts))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.node_files("pool-dmz"), ["node-001.json"])
        self.assertEqual(self.manifest("pool-dmz")["targets"], ["web-01"])

    def test_unsafe_pool_id_is_rejected(self):
        proc = self.run_script("collect_via_ssh.sh", "-p", "pool;rm -rf /", "-H", str(self.hosts))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("may only contain", proc.stderr)


class TestCollectViaKubectl(CollectScriptTestCase):
    def setUp(self):
        super().setUp()
        self.log = self.root / "kubectl.log"
        self.env["STUB_LOG"] = str(self.log)
        _install_stub(self.bin, "kubectl", KUBECTL_STUB)

    def test_not_ready_and_failed_nodes_are_recorded(self):
        proc = self.run_script("collect_via_kubectl.sh", "-p", "pool-k8s", "-l", "pool=dmz")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        m = self.manifest("pool-k8s")
        self.assertEqual(m["targets"], ["node-a", "node-b", "node-c"])
        self.assertEqual(m["succeeded"], ["node-a"])
        self.assertEqual(m["failed"], ["node-b"])
        self.assertEqual(m["unreachable"], ["node-c"])

    def test_debug_pods_are_deleted_and_sysadmin_profile_used(self):
        self.run_script("collect_via_kubectl.sh", "-p", "pool-k8s", "-l", "pool=dmz")
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("--profile=sysadmin", log)
        self.assertIn("delete pod node-debugger-node-a-xyz", log)
        self.assertIn("delete pod node-debugger-node-b-xyz", log)

    def test_selector_is_required(self):
        proc = self.run_script("collect_via_kubectl.sh", "-p", "pool-k8s")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("-l", proc.stderr)


class TestCollectViaSsm(CollectScriptTestCase):
    def setUp(self):
        super().setUp()
        self.state = self.root / "aws_state"
        self.state.mkdir()
        self.env["STUB_STATE"] = str(self.state)
        _install_stub(self.bin, "aws", AWS_STUB)

    def test_offline_and_failed_instances_are_recorded(self):
        proc = self.run_script("collect_via_ssm.sh", "-p", "pool-ec2", "-f", "Name=tag:triage-pool,Values=dmz", "-s", "org1")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        m = self.manifest("pool-ec2")
        self.assertEqual(m["targets"], ["i-001", "i-002", "i-003", "i-004"])
        self.assertEqual(m["succeeded"], ["i-001", "i-002"])
        self.assertEqual(m["unreachable"], ["i-003"])
        self.assertEqual(m["failed"], ["i-004"])
        # Only SSM-online instances receive the command; the collector is piped, not written to disk.
        cmd = json.loads((self.state / "cmd.json").read_text(encoding="utf-8"))
        self.assertEqual(cmd["ids"], ["i-001", "i-002", "i-004"])
        self.assertIn("base64 -d | sh -s -- -p pool-ec2 -s org1", cmd["command"])

    def test_collected_files_are_valid_telemetry(self):
        self.run_script("collect_via_ssm.sh", "-p", "pool-ec2", "-f", "Name=tag:triage-pool,Values=dmz")
        telemetries, _ = load_node_telemetries_with_report(str(self.out))
        pool = telemetries["pool-ec2"]
        self.assertEqual(pool.observed_nodes_count, 2)
        self.assertEqual(pool.expected_nodes_count, 4)
        self.assertEqual(len(set(pool.node_ids)), 2)


if __name__ == "__main__":
    unittest.main()

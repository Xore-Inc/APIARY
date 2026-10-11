"""#3621: detect missing Compose DNS and rejoin only affected containers."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "ops/swarm/container-dns.sh"


class ContainerDNSTest(unittest.TestCase):
    def test_check_is_read_only_and_rejoin_restores_missing_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "missing").write_text("hp-elasticsearch\nhp-filebeat\n")
            (root / "docker").write_text("""#!/usr/bin/env bash
case "$1 $2" in
  'network ls') printf 'bridge\\napp\\n' ;;
  'network inspect') printf 'hp-filebeat\\nhp-elasticsearch\\nbuilder\\n' ;;
  'container inspect')
    case "$3" in builder) echo '<no value>' ;; *)
      case "$5" in *Labels*) echo app ;; *) echo 123 ;; esac ;;
    esac ;;
  'restart hp-'*) echo "$2" >> "$TEST_DIR/restarted"
    grep -vx "$2" "$TEST_DIR/missing" > "$TEST_DIR/next"
    mv "$TEST_DIR/next" "$TEST_DIR/missing" ;;
  *) exit 2 ;;
esac
""")
            (root / "nsenter").write_text("""#!/usr/bin/env bash
name=${@: -1}
if grep -Fxq "$name" "$TEST_DIR/missing"; then exit 10; fi
""")
            for name in ("docker", "nsenter"):
                (root / name).chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", TEST_DIR=tmp)
            check = subprocess.run(["bash", str(SCRIPT), "check"], env=env, capture_output=True, text=True)
            self.assertEqual(check.returncode, 1, check.stderr)
            self.assertIn("hp-elasticsearch is missing", check.stderr)
            self.assertIn("hp-filebeat is missing", check.stderr)
            self.assertFalse((root / "restarted").exists())
            rejoin = subprocess.run(["bash", str(SCRIPT), "rejoin"], env=env, capture_output=True, text=True)
            self.assertEqual(rejoin.returncode, 0, rejoin.stderr)
            self.assertEqual((root / "restarted").read_text().splitlines(), ["hp-elasticsearch", "hp-filebeat"])
            self.assertEqual((root / "missing").read_text(), "")


if __name__ == "__main__":
    unittest.main()

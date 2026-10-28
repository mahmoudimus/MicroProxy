"""The image wrapper must reject unsupported inputs before simulator setup."""

import os
from pathlib import Path
import subprocess
import unittest


class WrapperContractTest(unittest.TestCase):
    def test_unsupported_inputs_need_no_setup_certificates_or_network(self):
        wrapper = Path(__file__).with_name("run_endpoint.sh")
        for role, case in [("client", "unknown-case"), ("server", "unknown-case"),
                           ("unknown-role", "handshake"), ("server", "keyupdate"),
                           ("client", "v2"), ("server", "connectionmigration")]:
            with self.subTest(role=role, case=case):
                env = dict(os.environ, ROLE=role, TESTCASE=case)
                env.pop("MICROPROXY_INTEROP_SKIP_SETUP", None)
                result = subprocess.run(["bash", str(wrapper)], env=env,
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(127, result.returncode, result.stderr)
                self.assertEqual("", result.stdout)
                self.assertEqual("", result.stderr)


if __name__ == "__main__":
    unittest.main()

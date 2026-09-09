from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

RUNNER = Path(__file__).resolve().parents[1] / "bin" / "flow_driver.py"
CONTRACTS = RUNNER.parents[1]
SPEC = importlib.util.spec_from_file_location("contract_google_flow_dispatch", RUNNER)
assert SPEC and SPEC.loader
flow_driver = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = flow_driver
SPEC.loader.exec_module(flow_driver)


class GoogleFlowDispatchTests(unittest.TestCase):
    def test_manifest_records_google_as_mixed_only_nonqualifying_dispatch(self) -> None:
        manifest = json.loads((CONTRACTS / "manifest.json").read_text(encoding="utf-8"))
        binding = manifest["phase7DevelopmentFlowDriver"]["googleMixedFlow"]
        self.assertEqual(binding["id"], "oauth-google")
        self.assertEqual(binding["topologies"], ["express-fastapi", "fastapi-express"])
        self.assertFalse(binding["independentRuntimeCorpus"])
        self.assertFalse(binding["qualifyingEvidence"])
        self.assertEqual(binding["unverified"], ["provider-error-state-lifecycle"])
        self.assertNotIn("oauth-google", flow_driver.FLOWS)
        self.assertTrue((CONTRACTS / binding["launchPolicy"]).is_file())
        for test_path in binding["tests"]:
            self.assertTrue((CONTRACTS / test_path).is_file())

    def test_common_entrypoint_preserves_owned_launcher_result(self) -> None:
        result = {
            "flow": "oauth-google",
            "ordering": "express-fastapi",
            "passed": True,
            "qualifying": False,
            "unverified": ["provider-error-state-lifecycle"],
            "assertions": {
                "start": True,
                "providerCalls": True,
                "providerSubjectLinked": True,
                "callerStatePreserved": True,
                "pkceRequired": True,
                "oauthSuccessStateReplayRejected": True,
                "handoffReplayRejected": True,
                "realAccessJwtVerified": True,
                "realRefreshJwtVerified": True,
                "mixedRuntimeExchange": True,
            },
        }
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            config = directory / "google.json"
            output = directory / "google.jsonl"
            config.write_text("{}", encoding="utf-8")
            config.chmod(0o600)
            launcher = mock.Mock()
            launcher.main.side_effect = lambda _argv: print(json.dumps(result)) or 0
            with mock.patch.object(
                flow_driver, "_load_oauth_launcher", return_value=launcher
            ):
                status = flow_driver.main(
                    [
                        "--flow",
                        "oauth-google",
                        "--oauth-google-launch-config",
                        str(config),
                        "--jsonl",
                        str(output),
                    ]
                )

            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), result)
            launcher.main.assert_called_once_with(["--config", str(config)])

    def test_google_dispatch_refuses_password_runtime_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            config = directory / "google.json"
            output = directory / "google.jsonl"
            config.write_text("{}", encoding="utf-8")
            config.chmod(0o600)
            status = flow_driver.main(
                [
                    "--flow",
                    "oauth-google",
                    "--oauth-google-launch-config",
                    str(config),
                    "--express",
                    "http://127.0.0.1:4400",
                    "--jsonl",
                    str(output),
                ]
            )
            self.assertEqual(status, 2)
            self.assertFalse(output.exists())

    def test_google_dispatch_rejects_promoted_or_malformed_result(self) -> None:
        otherwise_valid = {
            "flow": "oauth-google",
            "ordering": "express-fastapi",
            "passed": True,
            "qualifying": False,
            "unverified": ["provider-error-state-lifecycle"],
            "assertions": {name: True for name in flow_driver.GOOGLE_ASSERTIONS},
        }
        cases = (
            {"passed": True, "qualifying": True},
            {"flow": "oauth-google", "passed": True, "qualifying": False},
            {**otherwise_valid, "ordering": []},
            {**otherwise_valid, "ordering": {}},
        )
        for child_result in cases:
            with self.subTest(child_result=child_result):
                launcher = mock.Mock()
                launcher.main.side_effect = lambda _argv, value=child_result: (
                    print(json.dumps(value)) or 0
                )
                with (
                    mock.patch.object(
                        flow_driver, "_load_oauth_launcher", return_value=launcher
                    ),
                    self.assertRaises(flow_driver.ContractFailure),
                ):
                    flow_driver.run_google_dispatch(Path("/private/google.json"))

    def test_interrupt_propagates_through_in_process_launcher(self) -> None:
        launcher = mock.Mock()
        launcher.main.side_effect = KeyboardInterrupt
        with (
            mock.patch.object(
                flow_driver, "_load_oauth_launcher", return_value=launcher
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            flow_driver.run_google_dispatch(Path("/private/google.json"))
        launcher.main.assert_called_once_with(["--config", "/private/google.json"])

    def test_google_flow_cannot_mix_with_other_flow_or_caller_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            config = directory / "google.json"
            output = directory / "google.jsonl"
            config.write_text("{}", encoding="utf-8")
            config.chmod(0o600)
            for extra in (
                ["--flow", "password-direct-login-token"],
                ["--provenance", "runId=caller-claimed"],
                ["--topology", "express-fastapi"],
            ):
                with self.subTest(extra=extra):
                    status = flow_driver.main(
                        [
                            "--flow",
                            "oauth-google",
                            "--oauth-google-launch-config",
                            str(config),
                            "--jsonl",
                            str(output),
                            *extra,
                        ]
                    )
                    self.assertEqual(status, 2)
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

CONTRACTS = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "admin_cli_contract", CONTRACTS / "bin" / "flow_driver.py"
)
assert SPEC and SPEC.loader
driver = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = driver
SPEC.loader.exec_module(driver)


def result(topology: str) -> dict[str, object]:
    return {
        "flow": driver.ADMIN_FLOW,
        "topology": topology,
        "passed": True,
        "qualifying": False,
        "unverified": list(driver.ADMIN_UNVERIFIED),
        "assertions": dict.fromkeys(driver.ADMIN_ASSERTIONS, True),
    }


class AdminDispatchTests(unittest.TestCase):
    def test_actual_fixture_setup_shape_is_accepted_by_flow(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "admin_dispatch_fixture_contract",
            CONTRACTS / "adapters" / "admin_flow_fixture.py",
        )
        assert spec and spec.loader
        fixture = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = fixture
        spec.loader.exec_module(fixture)
        role_id = "20000000-0000-4000-8000-000000000001"
        config = SimpleNamespace(audience="contract", email_domain="example.invalid")
        with (
            mock.patch.object(fixture.shared, "reset"),
            mock.patch.object(fixture.shared, "seed"),
            mock.patch.object(fixture.shared, "psql", return_value=role_id),
        ):
            setup = fixture.setup(config, "admin-flow-users")
        module = driver._load_admin_flow()
        adapter = mock.Mock()
        adapter.invoke.return_value = setup
        admin, target, observed_role = module._setup(adapter)
        self.assertEqual(admin, setup["admin"])
        self.assertEqual(target, setup["target"])
        self.assertEqual(observed_role, role_id)
        self.assertEqual(admin["roles"], [{"serviceKey": "temis", "name": "admin"}])
        with mock.patch.object(
            fixture.shared,
            "psql",
            side_effect=[
                f"{admin['userId']}|active\n{target['userId']}|active",
                (
                    f"{admin['userId']}|{role_id}|temis|admin\n"
                    f"{target['userId']}|20000000-0000-4000-8000-000000000002|temis|user"
                ),
                "",
                "",
            ],
        ):
            state = fixture.snapshot(config, "admin-flow-state")
        adapter.invoke.return_value = state
        self.assertEqual(module._state(adapter), state)

    def test_manifest_records_admin_as_nonqualifying_separate_binding(self) -> None:
        manifest = json.loads((CONTRACTS / "manifest.json").read_text())
        binding = manifest["phase7DevelopmentFlowDriver"]["adminDevelopmentFlow"]
        self.assertEqual(binding["id"], driver.ADMIN_FLOW)
        self.assertEqual(binding["topologies"], list(driver.ADMIN_TOPOLOGIES))
        self.assertFalse(binding["qualifyingEvidence"])
        self.assertFalse(binding["independentRuntimeCorpus"])
        self.assertNotIn(binding["id"], driver.FLOWS)
        for path in [binding["runner"], binding["fixtureAdapter"], *binding["tests"]]:
            self.assertTrue((CONTRACTS / path).is_file())

    def test_runner_contract_constants_match_dispatch_whitelist(self) -> None:
        module = driver._load_admin_flow()
        self.assertEqual(set(module.ASSERTIONS), driver.ADMIN_ASSERTIONS)
        self.assertEqual(tuple(module.UNVERIFIED), driver.ADMIN_UNVERIFIED)

    def test_failure_is_sanitized_and_interrupt_is_not_swallowed(self) -> None:
        for failure in (RuntimeError("private-fixture-secret"), KeyboardInterrupt()):
            with (
                self.subTest(failure=type(failure)),
                tempfile.TemporaryDirectory() as raw,
            ):
                output = Path(raw) / "result.jsonl"
                module = mock.Mock()
                module.run_admin_flow.side_effect = failure
                with (
                    mock.patch.object(
                        driver,
                        "load_adapter_environment",
                        return_value={"CONTRACT_FASTAPI_RUNTIME": "1"},
                    ),
                    mock.patch.object(
                        driver,
                        "FixtureAdapter",
                        return_value=mock.Mock(isolation_identity=("db", "redis")),
                    ),
                    mock.patch.object(driver, "_load_admin_flow", return_value=module),
                    mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
                    mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
                ):
                    if isinstance(failure, KeyboardInterrupt):
                        with self.assertRaises(KeyboardInterrupt):
                            driver.main(self.arguments(output))
                    else:
                        self.assertEqual(driver.main(self.arguments(output)), 2)
                    self.assertNotIn(
                        "private-fixture-secret", stdout.getvalue() + stderr.getvalue()
                    )
                self.assertFalse(output.exists())

    def arguments(self, output: Path) -> list[str]:
        arguments = [
            "--flow",
            driver.ADMIN_FLOW,
            "--issuer",
            "https://issuer.example.invalid",
            "--jsonl",
            str(output),
        ]
        for runtime, port in (("express", 4400), ("fastapi", 4401)):
            arguments.extend(
                [
                    f"--{runtime}",
                    f"http://127.0.0.1:{port}",
                    f"--{runtime}-adapter",
                    str(CONTRACTS / "adapters" / "admin_flow_fixture.py"),
                    f"--{runtime}-adapter-config",
                    f"/private/{runtime}.json",
                ]
            )
        return arguments

    def test_common_cli_routes_all_topologies_without_promoting_evidence(self) -> None:
        module = mock.Mock()
        module.run_admin_flow.side_effect = lambda topology, *_args, **_kwargs: result(
            topology
        )
        adapter = mock.Mock(isolation_identity=("isolated-db", "isolated-redis"))
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "result.jsonl"
            with (
                mock.patch.object(
                    driver,
                    "load_adapter_environment",
                    return_value={"CONTRACT_FASTAPI_RUNTIME": "1"},
                ),
                mock.patch.object(driver, "FixtureAdapter", return_value=adapter),
                mock.patch.object(driver, "_load_admin_flow", return_value=module),
            ):
                status = driver.main(self.arguments(output))
            self.assertEqual(status, 0)
            self.assertEqual(
                [json.loads(line) for line in output.read_text().splitlines()],
                [result(t) for t in driver.ADMIN_TOPOLOGIES],
            )
            self.assertEqual(module.run_admin_flow.call_count, 4)
            for call in module.run_admin_flow.call_args_list:
                participants = set(call.args[0].split("-"))
                self.assertEqual(set(call.args[1]), participants)
                self.assertEqual(set(call.args[2]), participants)
            self.assertNotIn(driver.ADMIN_FLOW, driver.FLOWS)

    def test_ambiguous_modes_and_invalid_topologies_fail_before_fixture_creation(
        self,
    ) -> None:
        cases = (
            ["--flow", driver.FLOWS[0]],
            ["--flow", "oauth-naver"],
            ["--private-mail-launch-config", "/private/mail"],
            ["--oauth-launch-config", "/private/oauth"],
            ["--provenance", "sourceRevision=pretend"],
            ["--topology", "fastapi-fastapi"],
            ["--topology", "express", "--topology", "express"],
            ["--timeout", "nan"],
            ["--timeout", "61"],
        )
        for extra in cases:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as raw:
                output = Path(raw) / "result.jsonl"
                with mock.patch.object(driver, "FixtureAdapter") as adapter:
                    self.assertEqual(driver.main([*self.arguments(output), *extra]), 2)
                adapter.assert_not_called()
                self.assertFalse(output.exists())

    def test_wrong_adapter_or_loader_environment_never_enters_flow(self) -> None:
        cases: tuple[tuple[dict[str, str], list[str]], ...] = (
            ({"CONTRACT_FASTAPI_RUNTIME": "0"}, []),
            ({"CONTRACT_FASTAPI_RUNTIME": "1", "PYTHONPATH": "/private/injection"}, []),
            (
                {"CONTRACT_FASTAPI_RUNTIME": "1"},
                ["--express-adapter", "/private/other.py"],
            ),
        )
        for environment, extra in cases:
            with (
                self.subTest(environment=environment),
                tempfile.TemporaryDirectory() as raw,
            ):
                output = Path(raw) / "result.jsonl"
                with (
                    mock.patch.object(
                        driver, "load_adapter_environment", return_value=environment
                    ),
                    mock.patch.object(driver, "_load_admin_flow") as load,
                ):
                    self.assertEqual(driver.main([*self.arguments(output), *extra]), 2)
                load.assert_not_called()
                self.assertFalse(output.exists())

    def test_shared_store_mismatch_fails_before_any_single_or_mixed_trial(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "result.jsonl"
            with (
                mock.patch.object(
                    driver,
                    "load_adapter_environment",
                    return_value={"CONTRACT_FASTAPI_RUNTIME": "1"},
                ),
                mock.patch.object(
                    driver,
                    "FixtureAdapter",
                    side_effect=[
                        mock.Mock(isolation_identity=("db-one", "redis-one")),
                        mock.Mock(isolation_identity=("db-two", "redis-two")),
                    ],
                ),
                mock.patch.object(driver, "_load_admin_flow") as load,
            ):
                self.assertEqual(driver.main(self.arguments(output)), 2)
            load.assert_not_called()
            self.assertFalse(output.exists())

    def test_dispatch_preserves_runtime_specific_adapters_and_secrets(self) -> None:
        adapters = [
            mock.Mock(
                isolation_identity=("db", "redis"), refresh_secret="express-secret"
            ),
            mock.Mock(
                isolation_identity=("db", "redis"), refresh_secret="fastapi-secret"
            ),
        ]
        module = mock.Mock()
        module.run_admin_flow.return_value = result("express-fastapi")
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "result.jsonl"
            with (
                mock.patch.object(
                    driver,
                    "load_adapter_environment",
                    return_value={"CONTRACT_FASTAPI_RUNTIME": "1"},
                ),
                mock.patch.object(driver, "FixtureAdapter", side_effect=adapters),
                mock.patch.object(driver, "_load_admin_flow", return_value=module),
            ):
                self.assertEqual(
                    driver.main(
                        [*self.arguments(output), "--topology", "express-fastapi"]
                    ),
                    0,
                )
            received = module.run_admin_flow.call_args.args[2]
            self.assertIs(received["express"], adapters[0])
            self.assertIs(received["fastapi"], adapters[1])

    def test_malformed_promoted_or_sensitive_results_never_write_pass_output(
        self,
    ) -> None:
        cases = (
            {**result("express"), "qualifying": True},
            {**result("express"), "topology": "fastapi"},
            {**result("express"), "unverified": []},
            {**result("express"), "assertions": {"arbitrary": True}},
            {**result("express"), "accessToken": "not-public"},
        )
        for value in cases:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as raw:
                output = Path(raw) / "result.jsonl"
                module = mock.Mock()
                module.run_admin_flow.return_value = value
                with (
                    mock.patch.object(
                        driver,
                        "load_adapter_environment",
                        return_value={"CONTRACT_FASTAPI_RUNTIME": "1"},
                    ),
                    mock.patch.object(
                        driver,
                        "FixtureAdapter",
                        return_value=mock.Mock(isolation_identity=("db", "redis")),
                    ),
                    mock.patch.object(driver, "_load_admin_flow", return_value=module),
                ):
                    self.assertEqual(
                        driver.main([*self.arguments(output), "--topology", "express"]),
                        2,
                    )
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

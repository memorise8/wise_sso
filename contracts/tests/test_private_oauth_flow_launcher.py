from __future__ import annotations

import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import unittest
import urllib.request
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest import mock
from urllib import parse

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "contracts" / "bin" / "private_oauth_flow_launcher.py"
SPEC = importlib.util.spec_from_file_location(
    "contract_private_oauth_launcher", MODULE_PATH
)
assert SPEC and SPEC.loader
launcher_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = launcher_module
SPEC.loader.exec_module(launcher_module)


def _port() -> int:
    with socket.socket() as candidate:
        candidate.bind(("127.0.0.1", 0))
        return cast(tuple[str, int], candidate.getsockname())[1]


class BaseAdapter:
    refresh_secret = "launcher-test-refresh"

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.calls: list[tuple[str, str]] = []

    def invoke(self, command: str, name: str) -> Any:
        self.calls.append((command, name))
        if command == "setup":
            return {"runId": self.run_id}
        if command == "teardown":
            return {"status": "clean"}
        if name == "oauth-google-residual":
            return {
                "oauthStates": 0,
                "handoffs": 0,
                "activeRefreshTokens": 0,
                "activeTokenHashes": [],
                "providerRecords": 0,
            }
        raise AssertionError((command, name))


class PrivateOAuthLauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.config = self.root / "provider.json"
        self.config.write_text(
            json.dumps(
                {
                    "scenarios": [
                        {
                            "provider": "google",
                            "issuer": "https://accounts.google.com",
                            "code": "google-code",
                            "accessToken": "google-access",
                            "profile": {
                                "sub": "google-subject",
                                "email": "google@example.invalid",
                                "email_verified": True,
                            },
                            "clientId": "google-client",
                            "clientSecret": "google-secret",
                            "redirectUri": "http://127.0.0.1:4000/auth/google/callback",
                            "tokenOutcome": "success",
                            "userOutcome": "success",
                        }
                    ]
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        self.config.chmod(0o600)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def specs(self) -> tuple[Any, Any]:
        helper = ROOT / "contracts" / "tests" / "oauth_google_provider_probe.py"
        runtime_path = str(ROOT / "fastapi-auth-server" / ".venv" / "bin")
        inherited_path = os.environ.get("PATH", "")
        producer_port = _port()
        consumer_port = _port()
        while consumer_port == producer_port:
            consumer_port = _port()
        producer = launcher_module.RuntimeSpec.create(
            name="express",
            command=(
                str(helper),
                "--role",
                "producer",
                "--port",
                str(producer_port),
                "--provider-config",
                str(self.config),
            ),
            cwd=ROOT,
            health_url=f"http://127.0.0.1:{producer_port}/health",
            environment={"PATH": f"{runtime_path}:{inherited_path}"},
        )
        consumer = launcher_module.RuntimeSpec.create(
            name="fastapi",
            command=(
                str(helper),
                "--role",
                "consumer",
                "--port",
                str(consumer_port),
                "--provider-config",
                str(self.config),
            ),
            cwd=ROOT,
            health_url=f"http://127.0.0.1:{consumer_port}/health",
            environment={"PATH": f"{runtime_path}:{inherited_path}"},
        )
        return producer, consumer

    def test_actual_a04_child_records_are_consumed_by_owned_adapter(self) -> None:
        producer, consumer = self.specs()
        run_id = "oauth-launcher-run-001"
        owned_pids: list[int] = []
        with launcher_module.PrivateOAuthFlowLauncher(
            run_id=run_id,
            producer_role="express",
            producer=producer,
            consumer_role="fastapi",
            consumer=consumer,
        ) as launcher:
            adapter = launcher_module.OwnedOAuthFixtureAdapter(
                BaseAdapter(run_id), launcher
            )
            bindings = launcher.runtime_bindings
            owned_pids = [binding.pid for binding in bindings.values()]
            self.assertEqual(len(set(owned_pids)), 2)
            self.assertTrue(
                all(
                    binding.pid == binding.process_group
                    for binding in bindings.values()
                )
            )
            adapter.invoke("setup", "google-oauth-user")
            producer_origin = launcher.origins["express"]
            with urllib.request.urlopen(
                f"{producer_origin}/trigger", timeout=3
            ) as response:
                self.assertEqual(response.status, 200)
            snapshot = adapter.invoke("snapshot", "oauth-google-provider-invocations")
            self.assertEqual(
                snapshot,
                {
                    "source": "launcher-owned-private-provider-record-pipe-v1",
                    "consumed": True,
                    "records": [
                        {
                            "schemaVersion": 1,
                            "runId": run_id,
                            "runtime": "express",
                            "source": "provider-transport",
                            "provider": "google",
                            "operation": "token",
                            "sequence": 1,
                        },
                        {
                            "schemaVersion": 1,
                            "runId": run_id,
                            "runtime": "express",
                            "source": "provider-transport",
                            "provider": "google",
                            "operation": "user-info",
                            "sequence": 2,
                        },
                    ],
                },
            )
            adapter.invoke("teardown", "google-oauth-user")
        self.assertTrue(
            all(not (Path("/proc") / str(pid)).exists() for pid in owned_pids)
        )
        for runtime in (producer, consumer):
            parsed = parse.urlsplit(runtime.health_url)
            assert parsed.hostname is not None and parsed.port is not None
            self.assertEqual(
                launcher_module.mail._listening_socket_inodes(
                    parsed.port, parsed.hostname
                ),
                set(),
            )

    def test_cross_run_fixture_binding_is_rejected(self) -> None:
        producer, consumer = self.specs()
        with launcher_module.PrivateOAuthFlowLauncher(
            run_id="oauth-launcher-run-002",
            producer_role="express",
            producer=producer,
            consumer_role="fastapi",
            consumer=consumer,
        ) as launcher:
            adapter = launcher_module.OwnedOAuthFixtureAdapter(
                BaseAdapter("different-run-identifier"), launcher
            )
            with self.assertRaisesRegex(launcher_module.OAuthLaunchError, "runId"):
                adapter.invoke("setup", "google-oauth-user")

    def test_alias_existing_listener_and_same_process_are_rejected(self) -> None:
        producer, _consumer = self.specs()
        with self.assertRaisesRegex(Exception, "literal loopback"):
            launcher_module.RuntimeSpec.create(
                name="fastapi",
                command=producer.command,
                cwd=ROOT,
                health_url="http://localhost:4401/health",
            )

        class Process:
            pid = os.getpid()

        same = cast(Any, Process())
        with self.assertRaisesRegex(
            launcher_module.OAuthLaunchError, "not independent"
        ):
            launcher_module.PrivateOAuthFlowLauncher._assert_independent(same, same)

    def test_start_failure_drains_the_already_started_process(self) -> None:
        producer, consumer = self.specs()
        command = list(consumer.command)
        command[command.index("consumer")] = "invalid-role"
        failing_consumer = launcher_module.RuntimeSpec.create(
            name="fastapi",
            command=command,
            cwd=consumer.cwd,
            health_url=consumer.health_url,
            environment=consumer.environment,
        )
        launcher = launcher_module.PrivateOAuthFlowLauncher(
            run_id="oauth-launcher-run-003",
            producer_role="express",
            producer=producer,
            consumer_role="fastapi",
            consumer=failing_consumer,
            readiness_timeout=2,
        )
        with self.assertRaisesRegex(
            launcher_module.OAuthLaunchError, "exited before readiness"
        ):
            launcher.start()
        self.assertEqual(launcher._processes, {})

    def test_invalid_health_origin_is_rejected_before_channel_creation(self) -> None:
        producer, consumer = self.specs()
        for health_url in (
            "http://127.0.0.1/health",
            "http://127.0.0.1:0/health",
            "http://127.0.0.1:99999/health",
            "http://localhost:4401/health",
            "https://127.0.0.1:4401/health",
            consumer.health_url.rsplit("/", 1)[0] + "/other-health",
        ):
            with (
                self.subTest(health_url=health_url),
                mock.patch.object(
                    launcher_module.records, "PrivateProviderRecordChannel"
                ) as channel,
                self.assertRaises(launcher_module.OAuthLaunchError),
            ):
                launcher_module.PrivateOAuthFlowLauncher(
                    run_id="invalid-origin-run",
                    producer_role="express",
                    producer=replace(producer, health_url=health_url),
                    consumer_role="fastapi",
                    consumer=consumer,
                )
            channel.assert_not_called()

    def test_baseexception_during_pre_reap_cleanup_is_retried(self) -> None:
        producer, consumer = self.specs()
        launcher = launcher_module.PrivateOAuthFlowLauncher(
            run_id="oauth-launcher-run-004",
            producer_role="express",
            producer=producer,
            consumer_role="fastapi",
            consumer=consumer,
        ).start()
        original = launcher_module.mail.runtime_helpers._terminate_process_group
        calls = 0

        def interrupt_once(process: Any, pidfd: int, timeout: float) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise KeyboardInterrupt()
            original(process, pidfd, timeout)

        with mock.patch.object(
            launcher_module.mail.runtime_helpers,
            "_terminate_process_group",
            side_effect=interrupt_once,
        ):
            launcher._bounded_close()
        self.assertGreaterEqual(calls, 3)
        self.assertEqual(launcher._processes, {})

    def test_reaped_pidfd_close_failure_is_not_retried_by_number(self) -> None:
        producer, consumer = self.specs()
        launcher = launcher_module.PrivateOAuthFlowLauncher(
            run_id="oauth-launcher-run-005",
            producer_role="express",
            producer=producer,
            consumer_role="fastapi",
            consumer=consumer,
        )

        class Process:
            pid = 99123

        launcher._processes["express"] = (cast(Any, Process()), 77123)
        with (
            mock.patch.object(
                launcher_module.mail.runtime_helpers, "_terminate_process_group"
            ),
            mock.patch.object(
                launcher_module.os, "close", side_effect=OSError("injected")
            ) as close_fd,
            self.assertRaises(launcher_module.OAuthCleanupError),
        ):
            launcher._drain_role("express")
        launcher._drain_role("express")
        close_fd.assert_called_once_with(77123)
        launcher._terminal_cleanup_error = None
        launcher.close()

    def test_bounded_cleanup_exhaustion_preserves_primary_and_reports_cleanup(
        self,
    ) -> None:
        producer, consumer = self.specs()
        launcher = launcher_module.PrivateOAuthFlowLauncher(
            run_id="oauth-launcher-run-006",
            producer_role="express",
            producer=producer,
            consumer_role="fastapi",
            consumer=consumer,
        )
        primary = ValueError("primary")
        with (
            mock.patch.object(
                launcher,
                "close",
                side_effect=launcher_module.OAuthCleanupError("injected cleanup"),
            ),
            self.assertRaises(ValueError) as captured,
        ):
            launcher._bounded_close(primary)
        self.assertIs(captured.exception, primary)
        self.assertIn("oauth-launcher-cleanup-failure", primary.__notes__)
        self.assertIsInstance(primary.__cause__, launcher_module.OAuthCleanupError)
        launcher.close()

    def test_adapter_never_resets_fixture_when_runtime_drain_fails(self) -> None:
        producer, consumer = self.specs()
        launcher = launcher_module.PrivateOAuthFlowLauncher(
            run_id="oauth-launcher-run-007",
            producer_role="express",
            producer=producer,
            consumer_role="fastapi",
            consumer=consumer,
        ).start()

        class FailingAdapter(BaseAdapter):
            def invoke(self, command: str, name: str) -> Any:
                if command == "teardown":
                    raise ValueError("fixture teardown failed")
                return super().invoke(command, name)

        adapter = launcher_module.OwnedOAuthFixtureAdapter(
            FailingAdapter("oauth-launcher-run-007"), launcher
        )
        original_close = launcher.close
        self.addCleanup(original_close)
        with (
            mock.patch.object(
                launcher,
                "close",
                side_effect=launcher_module.OAuthCleanupError("injected cleanup"),
            ),
            mock.patch.object(adapter._adapter, "invoke") as fixture_call,
            self.assertRaises(launcher_module.OAuthCleanupError),
        ):
            adapter.invoke("teardown", "google-oauth-user")
        fixture_call.assert_not_called()
        original_close()

    def test_adapter_drains_owned_children_before_fixture_teardown(self) -> None:
        producer, consumer = self.specs()
        with launcher_module.PrivateOAuthFlowLauncher(
            run_id="oauth-drain-before-reset",
            producer_role="express",
            producer=producer,
            consumer_role="fastapi",
            consumer=consumer,
        ) as launcher:
            base = BaseAdapter("oauth-drain-before-reset")
            adapter = launcher_module.OwnedOAuthFixtureAdapter(base, launcher)
            owned_pids = [process.pid for process, _fd in launcher._processes.values()]

            def teardown(_command: str, _name: str) -> dict[str, str]:
                self.assertEqual(launcher._processes, {})
                for pid in owned_pids:
                    self.assertFalse(Path(f"/proc/{pid}").exists())
                return {"status": "clean"}

            with mock.patch.object(base, "invoke", side_effect=teardown):
                self.assertEqual(
                    adapter.invoke("teardown", "google-oauth-user"),
                    {"status": "clean"},
                )

    def test_main_preflight_failure_does_not_start_or_reset_runtime(self) -> None:
        environment = {
            "CONTRACT_DATABASE_URL": "postgresql://127.0.0.1:5433/oauth_test_case",
            "CONTRACT_REDIS_URL": "redis://127.0.0.1:6380/13",
            "CONTRACT_SERVER_MAIL_MODE": "dev",
        }
        config = {
            "version": 1,
            "runId": "preflight-refused-run",
            "producerRole": "express",
            "consumerRole": "fastapi",
            "expectedIssuer": "https://issuer.example.invalid",
            "producer": {},
            "consumer": {},
            "fixtureAdapter": "/unused/fixture",
            "fixtureEnvironment": environment,
        }
        base = mock.Mock()
        base.invoke.return_value = {"status": "ok", "database": "wrong_database"}
        module = SimpleNamespace(FixtureAdapter=mock.Mock(return_value=base))
        with (
            mock.patch.object(launcher_module, "_load_config", return_value=config),
            mock.patch.object(launcher_module, "_validate_launch_policy") as policy,
            mock.patch.object(launcher_module, "_runtime_from_config"),
            mock.patch.object(launcher_module, "_load", return_value=module),
            mock.patch.object(launcher_module, "PrivateOAuthFlowLauncher") as launcher,
            mock.patch("sys.stdout", new=io.StringIO()) as output,
        ):
            self.assertEqual(launcher_module.main(["--config", "/unused/config"]), 2)
        launcher.assert_not_called()
        policy.assert_called_once_with(config)
        base.invoke.assert_called_once_with("preflight", "google-oauth-user")
        self.assertFalse(json.loads(output.getvalue())["passed"])

        with (
            mock.patch.object(launcher_module, "_load_config", return_value=config),
            mock.patch.object(
                launcher_module,
                "_validate_launch_policy",
                side_effect=launcher_module.OAuthLaunchError("policy refusal"),
            ),
            mock.patch.object(launcher_module, "_preflight_fixture") as preflight,
            mock.patch.object(launcher_module, "PrivateOAuthFlowLauncher") as launcher,
            mock.patch("sys.stdout", new=io.StringIO()),
        ):
            self.assertEqual(launcher_module.main(["--config", "/unused/config"]), 2)
        preflight.assert_not_called()
        launcher.assert_not_called()


if __name__ == "__main__":
    unittest.main()

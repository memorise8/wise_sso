import os

import anyio
import pytest

from wiseacct_sso.infrastructure.security import AsyncPasswordHasher

EXPRESS_GENERATED_PASSWORD_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$ABEiM0RVZneImaq7zN3u/w$"
    "zeuaFYFAbBFiUM3IwmEtHtc4d61aWWRsUGaZIOShyuI"
)


@pytest.mark.anyio
async def test_python_verifies_node_generated_hash_fixture() -> None:
    passwords = AsyncPasswordHasher()

    assert (
        await passwords.verify_password(EXPRESS_GENERATED_PASSWORD_HASH, "express-fixture-password")
        is True
    )


@pytest.mark.anyio
async def test_node_verifies_python_generated_hash_when_express_module_is_available() -> None:
    module_value = os.getenv("WISEACCT_EXPRESS_ARGON2_MODULE")
    if module_value is None:
        pytest.skip("set WISEACCT_EXPRESS_ARGON2_MODULE to an installed Express argon2.cjs")
    module = await anyio.Path(module_value).resolve(strict=True)
    if module.name != "argon2.cjs" or module.parent.name != "argon2":
        pytest.fail("WISEACCT_EXPRESS_ARGON2_MODULE must resolve to argon2/argon2.cjs")

    password = "python-fixture-password"
    encoded = await AsyncPasswordHasher().hash_password(password)
    script = (
        "const argon2 = require(process.argv[1]);"
        "argon2.verify(process.argv[2], process.argv[3])"
        ".then(ok => { process.stdout.write(ok ? 'true' : 'false'); })"
        ".catch(() => { process.exitCode = 2; });"
    )
    with anyio.fail_after(10):
        result = await anyio.run_process(
            ["/usr/bin/node", "-e", script, str(module), encoded, password],
            check=False,
        )

    assert result.returncode == 0
    assert result.stdout == b"true"
    assert result.stderr == b""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass

from fastapi import FastAPI

LifecycleHook = Callable[[], Awaitable[None]]


async def _noop_hook() -> None:
    return None


@dataclass(frozen=True)
class LifecycleHooks:
    startup: LifecycleHook = _noop_hook
    shutdown: LifecycleHook = _noop_hook


def create_lifespan(
    hooks: LifecycleHooks,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.accepting_requests = False
        await hooks.startup()
        app.state.accepting_requests = True
        try:
            yield
        finally:
            app.state.accepting_requests = False
            await hooks.shutdown()

    return lifespan

import pytest


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


def pytest_collection_modifyitems(items):
    """Every test here is async; marking them individually adds noise and nothing else."""
    for item in items:
        item.add_marker(pytest.mark.anyio)

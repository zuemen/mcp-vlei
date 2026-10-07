"""deploy/ at v0.3, read as files: where each public route goes, what each service is given, and
that the parallel overlays rename every container and move every port the live stack uses."""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[3]
GATEWAY = ROOT / "deploy" / "agentgateway"
PARALLEL = ROOT / "deploy" / "v03"


class Compose(yaml.SafeLoader):
    """Compose's merge tags (`!override`, `!reset`) read as the values they carry."""


def _tagged(loader: yaml.SafeLoader, node: yaml.Node):
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


Compose.add_constructor("!override", _tagged)
Compose.add_constructor("!reset", _tagged)


def load(path: Path):
    return yaml.load(path.read_text(encoding="utf-8"), Loader=Compose)


def test_both_public_routes_go_to_vlei_pop_and_neither_is_authorized():
    routes = {r["name"]: r for r in load(GATEWAY / "config.yaml")["binds"][0]["listeners"][0]["routes"]}
    for name, path in (("well-known", "/.well-known/vlei"),
                       ("proof-of-possession", "/.well-known/vlei/pop")):
        route = routes[name]
        assert route["matches"][0]["path"]["exact"] == path
        assert route["backends"] == [{"host": "vlei-pop:9100"}]
        assert "extAuthz" not in route["policies"] and "localRateLimit" in route["policies"]
    assert routes["labor-insurance"]["policies"]["extAuthz"]["failureMode"] == "deny"


def test_the_proof_route_has_its_own_small_public_bucket():
    """vlei-pop signs one challenge at a time (2-3 s) with four waiting: at the shared 60 a minute,
    one public caller at 1 request/s keeps it full and the local proxy's connect gets 503."""
    routes = {r["name"]: r for r in load(GATEWAY / "config.yaml")["binds"][0]["listeners"][0]["routes"]}
    pop = routes["proof-of-possession"]["policies"]["localRateLimit"]["conditional"]
    assert pop == [
        {"condition": '"cf-connecting-ip" in request.headers',
         "maxTokens": 5, "tokensPerFill": 5, "fillInterval": "60s"},
        {"maxTokens": 600, "tokensPerFill": 600, "fillInterval": "60s"},
    ]
    shared = routes["well-known"]["policies"]["localRateLimit"]
    assert routes["labor-insurance"]["policies"]["localRateLimit"] == shared
    assert shared["conditional"][0]["maxTokens"] == 60


def test_the_gateway_is_given_its_audience_and_a_replay_store_on_a_volume():
    compose = load(GATEWAY / "docker-compose.yml")
    authz = compose["services"]["vlei-authz"]
    assert any(e.startswith("VLEI_AUDIENCE_URLS=") for e in authz["environment"])
    assert "VLEI_REPLAY_DB=/state/replay.sqlite3" in authz["environment"]
    assert "vlei-authz-state:/state" in authz["volumes"]
    pop = compose["services"]["vlei-pop"]
    assert pop["build"]["dockerfile"] == "deploy/agentgateway/Dockerfile.pop"
    assert "vlei-pop-keystore:/usr/local/var/keri" in pop["volumes"]
    assert "mcp-vlei_default" in pop["networks"]
    assert set(compose["volumes"]) == {"vlei-authz-state", "vlei-pop-keystore"}
    assert "vlei-pop" in compose["services"]["agentgateway"]["depends_on"]


def test_the_gateway_proves_itself_for_exactly_the_urls_it_verifies_for():
    """vlei-pop signs proofs only for VLEI_AUDIENCE_URLS and vlei-authz accepts calls only for
    them: one list, written once (a YAML anchor), so the two cannot drift apart."""
    compose = load(GATEWAY / "docker-compose.yml")
    audience = [[e for e in compose["services"][name]["environment"]
                 if e.startswith("VLEI_AUDIENCE_URLS=")] for name in ("vlei-authz", "vlei-pop")]
    assert len(audience[0]) == 1 and audience[0] == audience[1]
    assert (GATEWAY / "docker-compose.yml").read_text(encoding="utf-8").count(
        "VLEI_AUDIENCE_URLS=${") == 1, "the list is written more than once"


def test_the_replay_store_directory_belongs_to_the_service_user():
    dockerfile = (GATEWAY / "Dockerfile.python").read_text(encoding="utf-8")
    assert dockerfile.index("mkdir -p /state && chown vlei /state") < dockerfile.index("USER vlei")


def test_the_pop_image_bakes_configuration_and_no_key():
    dockerfile = (GATEWAY / "Dockerfile.pop").read_text(encoding="utf-8")
    assert "COPY scripts/keri-config/incept-witnesses.json" in dockerfile
    assert "export-key.py" not in dockerfile
    ignore = (GATEWAY / "Dockerfile.pop.dockerignore").read_text(encoding="utf-8")
    for needle in ("credentials/", "**/keys/", "**/*.key", "**/.env"):
        assert needle in ignore.splitlines()


def test_the_parallel_overlays_rename_every_container_and_move_every_port():
    base = load(PARALLEL / "parallel.base.yml")
    assert base["name"] == "mcp-vlei-v03p"
    names = [service["container_name"] for service in base["services"].values()]
    assert len(names) == 4 and all(n.startswith("mcp-vlei-v03p-") for n in names)
    ports = [p for service in base["services"].values() for p in service.get("ports", [])]
    assert ports and all(int(p.split(":")[0]) >= 30000 for p in ports)
    regulator = load(PARALLEL / "parallel.regulator.yml")
    assert regulator["name"] == "mcp-vlei-v03p-regulator"
    assert regulator["networks"]["mcp-vlei_default"]["name"] == "mcp-vlei-v03p_default"
    assert regulator["services"]["agentgateway"]["ports"] == ["33000:3000"]
    assert regulator["services"]["labor-insurance-before"]["ports"] == ["127.0.0.1:38090:8081"]

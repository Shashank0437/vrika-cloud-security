import os

import neo4j
import pytest


@pytest.fixture
def graph():
    uri = os.environ.get("ATTACK_PATHS_TEST_NEO4J_URI")
    if not uri or os.environ.get("ATTACK_PATHS_TEST_ALLOW_RESET") != "1":
        pytest.skip(
            "Set ATTACK_PATHS_TEST_NEO4J_URI and ALLOW_RESET=1 for a disposable Neo4j"
        )
    with neo4j.GraphDatabase.driver(uri) as driver, driver.session() as session:
        assert session.run("MATCH (n) RETURN count(n) AS n").single()["n"] == 0
        try:
            yield session
        finally:
            session.run("MATCH (n) DETACH DELETE n").consume()

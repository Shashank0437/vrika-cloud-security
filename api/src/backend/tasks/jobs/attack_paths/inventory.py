"""Small graph-loading helpers for scoped cloud configuration evidence."""

import logging
import re

logger = logging.getLogger(__name__)


class CollectionError(Exception):
    def __init__(self, errors: dict[str, str]):
        self.errors = errors
        super().__init__("; ".join(f"{key}: {value}" for key, value in errors.items()))


def load_resources(session, root_label, root_id, label, rows, update_tag):
    for identifier in (root_label, label):
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", identifier):
            raise ValueError(f"Invalid graph label: {identifier}")
    session.run(
        f"""
        MATCH (root:{root_label} {{id: $root_id}})
        UNWIND $rows AS row
        MERGE (n:{label} {{id: row.id}})
        ON CREATE SET n.firstseen = $update_tag
        SET n += row, n.lastupdated = $update_tag
        MERGE (root)-[:RESOURCE]->(n)
        """,
        root_id=root_id,
        rows=rows,
        update_tag=update_tag,
    ).consume()


def collect_each(items, collect, exceptions):
    """Preserve successful siblings when one resource is inaccessible."""
    errors = {}
    for item in items:
        try:
            collect(item)
        except exceptions as exc:
            errors[str(item)] = str(exc)
    if errors:
        raise CollectionError(errors)


def run_steps(session, root_label, root_id, steps, exceptions, update_tag, progress):
    errors = {}
    failed = 0
    for index, (name, collect) in enumerate(steps, 1):
        message = None
        try:
            collect()
        except (*exceptions, CollectionError) as exc:
            failed += 1
            message = str(exc)
            errors[name] = message
            logger.warning("Attack Paths %s/%s: %s", root_id, name, message)
        load_resources(
            session,
            root_label,
            root_id,
            "CloudCollectionStatus",
            [
                {
                    "id": f"{root_id}/collection/{name}",
                    "service": name,
                    "status": "error" if message else "collected",
                    "error": message,
                }
            ],
            update_tag,
        )
        progress(3 + index * 90 // len(steps))
    if failed == len(steps):
        raise RuntimeError(f"All {root_label} Attack Paths services failed: {errors}")
    return errors

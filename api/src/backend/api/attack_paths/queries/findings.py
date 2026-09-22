import re


def return_paths_with_findings(*path_names: str) -> str:
    """Return selected paths with the failed findings linked to their nodes."""
    if not path_names or any(
        not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in path_names
    ):
        raise ValueError("Finding enrichment requires valid path variable names")

    paths = " + ".join(f"collect(DISTINCT {name})" for name in path_names)
    return f"""
        WITH {paths} AS paths
        UNWIND paths AS selected_path
        UNWIND nodes(selected_path) AS resource
        WITH paths, collect(DISTINCT resource) AS resources
        UNWIND resources AS resource
        OPTIONAL MATCH (resource)-[finding_relationship:HAS_FINDING]->(finding:ProwlerFinding {{status: 'FAIL'}})
        WHERE finding.muted = false
        RETURN paths, collect(DISTINCT finding) AS findings,
            collect(DISTINCT finding_relationship) AS finding_relationships
    """

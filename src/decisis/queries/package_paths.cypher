UNWIND $wanted AS target_id
MATCH (r:Repository {id: $repo}), (pkg:Package {id: target_id})
LET any_path = COLLECT {
  MATCH p = SHORTEST 1 (r)-[:DEPENDS_ON]->{1,$depth}(pkg)
  RETURN [n IN nodes(p) | n.id] AS ids
}
LET shipped_path = COLLECT {
  MATCH p = SHORTEST 1 (r)-[:DECISIS_SHIPPED_STEP]->{1,$depth}(pkg)
  RETURN [n IN nodes(p) | n.id] AS ids
}
RETURN target_id AS package, any_path[0] AS any_path, shipped_path[0] AS shipped_path

MATCH (r:Repository {id: $repo})
MATCH p = SHORTEST 1 (r)-[:DECISIS_SHIPPED_STEP]->{1,$depth}(pkg:Package)
MATCH (pkg)-[:AFFECTED_BY]->(a:Advisory)
RETURN pkg.id AS package, a.id AS advisory, [n IN nodes(p) | n.id] + [a.id] AS path
ORDER BY size(path)

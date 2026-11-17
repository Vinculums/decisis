MATCH p = (r:Repository {id: $repo})-[:DEPENDS_ON*1..$depth]->(pkg:Package)-[:AFFECTED_BY]->(a:Advisory)
RETURN pkg.id AS package, a.id AS advisory, [n IN nodes(p) | n.id] AS path
ORDER BY length(p)

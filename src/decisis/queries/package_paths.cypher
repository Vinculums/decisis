MATCH p = (r:Repository {id: $repo})-[:DEPENDS_ON*1..$depth]->(pkg:Package)
WHERE pkg.id IN $ids
RETURN pkg.id AS package, [n IN nodes(p) | n.id] AS path
ORDER BY length(p)

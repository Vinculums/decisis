MATCH p = (d:Decision {id: $decision})-[:ABOUT]->(c)<-[:DESCRIBED_BY]-(r:Repository)-[:DEPENDS_ON*1..$depth]->(pkg:Package {id: $package})-[:AFFECTED_BY]->(a:Advisory {id: $advisory})
RETURN [n IN nodes(p) | n.id] AS ids, [x IN relationships(p) | type(x)] AS rels
ORDER BY length(p)
LIMIT 1

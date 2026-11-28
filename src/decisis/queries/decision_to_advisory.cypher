MATCH (d:Decision {id: $decision})-[:ABOUT]->(c)<-[:DESCRIBED_BY]-(r:Repository)
MATCH p = SHORTEST 1 (r)-[:DEPENDS_ON]->{1,$depth}(pkg:Package {id: $package})
MATCH (pkg)-[:AFFECTED_BY]->(a:Advisory {id: $advisory})
RETURN [d.id, c.id] + [n IN nodes(p) | n.id] + [a.id] AS ids,
       ['ABOUT', 'DESCRIBED_BY'] + [x IN relationships(p) | type(x)] + ['AFFECTED_BY'] AS rels
ORDER BY size(ids)
LIMIT 1

MATCH p = (a {id: $source})-[*1..$hops]-(b {id: $target})
RETURN [n IN nodes(p) | n.id] AS ids, [r IN relationships(p) | type(r)] AS rels
ORDER BY length(p)
LIMIT $limit

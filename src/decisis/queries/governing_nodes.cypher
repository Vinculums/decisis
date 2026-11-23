MATCH (c)
WHERE ANY(x IN c.code_paths WHERE x = $path OR x STARTS WITH $dir OR $path STARTS WITH x + '/')
MATCH p = (g)-[*0..$hops]->(c)
WHERE length(p) = 0 OR g.kind IN $kinds
RETURN c.id AS anchor, g.id AS id, g.kind AS kind, length(p) AS hops,
       [n IN nodes(p) | n.id] AS ids, [r IN relationships(p) | type(r)] AS rels, [r IN relationships(p) | r.evidence] AS evidence
ORDER BY hops, id, anchor

MATCH p = (newer:Decision)-[:SUPERSEDES]->+(old:Decision)
RETURN newer.id AS newer, old.id AS old, length(p) AS hops, [n IN nodes(p) | n.id] AS chain
ORDER BY hops, newer, old

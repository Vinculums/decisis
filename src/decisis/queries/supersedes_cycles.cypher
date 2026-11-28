MATCH (d:Decision)
WHERE EXISTS { MATCH (d)-[:SUPERSEDES]->+(d) }
LET members = COLLECT {
  MATCH (m)
  WHERE m = d OR (EXISTS { MATCH (d)-[:SUPERSEDES]->+(m) } AND EXISTS { MATCH (m)-[:SUPERSEDES]->+(d) })
  RETURN DISTINCT m.id AS mid ORDER BY mid
}
RETURN DISTINCT members

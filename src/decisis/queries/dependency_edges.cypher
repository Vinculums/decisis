MATCH (a)-[:DEPENDS_ON]->(b)
WHERE b.id IN $ids
RETURN a.id AS source, b.id AS target

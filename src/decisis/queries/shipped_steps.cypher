MATCH (a)-[:DEPENDS_ON]->(b)
WHERE NOT (b:Package AND coalesce(b.dev, false) = true)
CREATE (a)-[:DECISIS_SHIPPED_STEP]->(b)

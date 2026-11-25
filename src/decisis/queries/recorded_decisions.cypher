MATCH (r:Repository {id: $repo})-[:RECORDS]->(d:Decision)
RETURN DISTINCT d.id AS decision, d.title AS title

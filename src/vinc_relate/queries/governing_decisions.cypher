MATCH (r:Repository {id: $repo})-[:DESCRIBED_BY]->(c)<-[:ABOUT]-(d:Decision)
RETURN DISTINCT d.id AS decision, d.title AS title, c.id AS via

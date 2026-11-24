MATCH (p:Package) WHERE p.id IN $ids
RETURN p.id AS package, p.dev AS dev

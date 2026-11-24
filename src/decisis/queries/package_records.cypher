MATCH (p:Package) WHERE p.id IN $ids
RETURN p.id AS package, p.dev AS dev, p.ecosystem AS ecosystem, p.name AS name, p.version AS version

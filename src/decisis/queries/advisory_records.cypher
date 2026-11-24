MATCH (a:Advisory) WHERE a.id IN $ids
RETURN a.id AS advisory, a.content_hash AS content_hash, a.severity AS severity, a.affected_json AS affected_json

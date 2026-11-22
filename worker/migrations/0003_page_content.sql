-- TipTap JSON alongside plain-text body used by FTS5 (ADR 0011).

ALTER TABLE articles ADD COLUMN content_json TEXT NOT NULL DEFAULT '';

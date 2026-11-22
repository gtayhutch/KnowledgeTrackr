-- Spaces partition Pages (still stored in the articles table) inside a
-- company. ADR 0008: Company → Space → Page.

CREATE TABLE spaces (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL REFERENCES companies (id),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  slug TEXT NOT NULL CHECK (length(slug) BETWEEN 1 AND 80),
  description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 500),
  created_at INTEGER NOT NULL,
  archived_at INTEGER,
  UNIQUE (company_id, slug)
);

CREATE INDEX spaces_company ON spaces (company_id);

-- One default Space per existing company.
INSERT INTO spaces (id, company_id, name, slug, description, created_at, archived_at)
SELECT
  lower(hex(randomblob(16))),
  id,
  'General',
  'general',
  '',
  created_at,
  NULL
FROM companies;

ALTER TABLE articles ADD COLUMN space_id TEXT REFERENCES spaces (id);
ALTER TABLE articles ADD COLUMN parent_id TEXT REFERENCES articles (id);
ALTER TABLE articles ADD COLUMN position TEXT NOT NULL DEFAULT '';
ALTER TABLE articles ADD COLUMN icon TEXT;
ALTER TABLE articles ADD COLUMN deleted_at INTEGER;

UPDATE articles
SET
  space_id = (
    SELECT s.id
    FROM spaces s
    WHERE s.company_id = articles.company_id
      AND s.slug = 'general'
    LIMIT 1
  ),
  position = id
WHERE space_id IS NULL;

CREATE INDEX articles_space_parent ON articles (space_id, parent_id, position);
CREATE INDEX articles_space_updated ON articles (space_id, updated_at DESC);

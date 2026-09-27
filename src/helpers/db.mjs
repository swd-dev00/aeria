import { DatabaseSync } from "node:sqlite";
export function openDatabase(filename) {
  const db = new DatabaseSync(filename);
  db.exec(`
    PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA journal_mode=DELETE;
    CREATE TABLE IF NOT EXISTS institutions(id TEXT PRIMARY KEY,name TEXT NOT NULL,connected INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS members(id TEXT PRIMARY KEY,institution_id TEXT NOT NULL REFERENCES institutions(id),name TEXT NOT NULL,active INTEGER NOT NULL,capabilities TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,member_id TEXT NOT NULL REFERENCES members(id),csrf_hash TEXT NOT NULL,expires_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,institution_id TEXT NOT NULL REFERENCES institutions(id),key_hash TEXT NOT NULL,created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS assignments(case_id TEXT NOT NULL REFERENCES cases(id),member_id TEXT NOT NULL REFERENCES members(id),PRIMARY KEY(case_id,member_id));
    CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),body TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS analyses(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),policy_id TEXT NOT NULL REFERENCES policies(id),body TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS receipts(analysis_id TEXT PRIMARY KEY REFERENCES analyses(id),body TEXT NOT NULL,hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),state TEXT NOT NULL CHECK(state IN ('SUBMITTED','ACKNOWLEDGED','CONTENT_DELETED')));
    CREATE TABLE IF NOT EXISTS request_content(request_id TEXT PRIMARY KEY REFERENCES requests(id),content TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS events(case_id TEXT NOT NULL REFERENCES cases(id),sequence INTEGER NOT NULL,body TEXT NOT NULL,hash TEXT NOT NULL,PRIMARY KEY(case_id,sequence));
  `);
  for (const table of ["events", "policies", "analyses", "receipts"])
    for (const operation of ["UPDATE", "DELETE"])
      db.exec(
        `CREATE TRIGGER IF NOT EXISTS ${table}_no_${operation} BEFORE ${operation} ON ${table} BEGIN SELECT RAISE(ABORT,'append-only record'); END`,
      );
  return db;
}
export function transaction(db, fn) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = fn();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

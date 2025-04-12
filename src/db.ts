import SqliteDb from "better-sqlite3";
import {
  Kysely,
  Migrator,
  SqliteDialect,
  Migration,
  MigrationProvider,
} from "kysely";

// Types

export type DatabaseSchema = {
  status: Status;
  auth_session: AuthSession;
  auth_state: AuthState;
  key_package: KeyPackage;
  message: Message;
};

export type KeyPackage = {
  uri: string;
  authorDid: string;
  package: string;
  createdAt: string;
  indexedAt: string;
};

export type Message = {
  uri: string;
  authorDid: string;
  message: string;
  createdAt: string;
  indexedAt: string;
};

export type Status = {
  uri: string;
  authorDid: string;
  status: string;
  nonce: string;
  createdAt: string;
  indexedAt: string;
};

export type AuthSession = {
  key: string;
  session: AuthSessionJson;
};

export type AuthState = {
  key: string;
  state: AuthStateJson;
};

type AuthStateJson = string;

type AuthSessionJson = string;

// Migrations

const migrations: Record<string, Migration> = {};

const migrationProvider: MigrationProvider = {
  async getMigrations() {
    return migrations;
  },
};

migrations["001"] = {
  async up(db: Kysely<unknown>) {
    await db.schema
      .createTable("status")
      .addColumn("uri", "varchar", (col) => col.primaryKey())
      .addColumn("authorDid", "varchar", (col) => col.notNull())
      .addColumn("status", "varchar", (col) => col.notNull())
      .addColumn("nonce", "varchar", (col) => col.notNull())
      .addColumn("createdAt", "varchar", (col) => col.notNull())
      .addColumn("indexedAt", "varchar", (col) => col.notNull())
      .execute();
    await db.schema
      .createTable("auth_session")
      .addColumn("key", "varchar", (col) => col.primaryKey())
      .addColumn("session", "varchar", (col) => col.notNull())
      .execute();
    await db.schema
      .createTable("auth_state")
      .addColumn("key", "varchar", (col) => col.primaryKey())
      .addColumn("state", "varchar", (col) => col.notNull())
      .execute();
    await db.schema
      .createTable("key_package")
      .addColumn("uri", "varchar", (col) => col.primaryKey())
      .addColumn("authorDid", "varchar", (col) => col.notNull())
      .addColumn("package", "varchar", (col) => col.notNull())
      .addColumn("createdAt", "varchar", (col) => col.notNull())
      .addColumn("indexedAt", "varchar", (col) => col.notNull())
      .execute();
    await db.schema
      .createTable("message")
      .addColumn("uri", "varchar", (col) => col.primaryKey())
      .addColumn("authorDid", "varchar", (col) => col.notNull())
      .addColumn("message", "varchar", (col) => col.notNull())
      .addColumn("createdAt", "varchar", (col) => col.notNull())
      .addColumn("indexedAt", "varchar", (col) => col.notNull())
      .execute();
  },
  async down(db: Kysely<unknown>) {
    await db.schema.dropTable("auth_state").execute();
    await db.schema.dropTable("auth_session").execute();
    await db.schema.dropTable("status").execute();
    await db.schema.dropTable("key_package").execute();
    await db.schema.dropTable("message").execute();
  },
};

// APIs

export const createDb = (location: string): Database => {
  return new Kysely<DatabaseSchema>({
    dialect: new SqliteDialect({
      database: new SqliteDb(location),
    }),
  });
};

export const migrateToLatest = async (db: Database) => {
  const migrator = new Migrator({ db, provider: migrationProvider });
  const { error } = await migrator.migrateToLatest();
  if (error) throw error;
};

export type Database = Kysely<DatabaseSchema>;

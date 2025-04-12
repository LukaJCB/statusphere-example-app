import pino from "pino";
import { IdResolver } from "@atproto/identity";
import { Firehose } from "@atproto/sync";
import type { Database } from "#/db";
import * as Status from "#/lexicon/types/xyz/statusphere/private/status";
import * as Message from "#/lexicon/types/xyz/statusphere/private/message";
import * as KeyPackage from "#/lexicon/types/xyz/statusphere/private/key";

export function createIngester(db: Database, idResolver: IdResolver) {
  const logger = pino({ name: "firehose ingestion" });
  return new Firehose({
    idResolver,
    handleEvent: async (evt) => {
      // Watch for write events
      if (evt.event === "create" || evt.event === "update") {
        const now = new Date();
        const record = evt.record;

        // If the write is a valid status update
        if (
          evt.collection === "xyz.statusphere.private.status" &&
          Status.isRecord(record) &&
          Status.validateRecord(record).success
        ) {
          // Store the status in our SQLite
          await db
            .insertInto("status")
            .values({
              uri: evt.uri.toString(),
              authorDid: evt.did,
              status: record.status,
              nonce: record.nonce,
              createdAt: record.createdAt,
              indexedAt: now.toISOString(),
            })
            .onConflict((oc) =>
              oc.column("uri").doUpdateSet({
                status: record.status,
                indexedAt: now.toISOString(),
              }),
            )
            .execute();
        } else if (
          evt.collection === "xyz.statusphere.private.message" &&
          Message.isRecord(record) &&
          Message.validateRecord(record).success
        ) {
          // Store the status in our SQLite
          await db
            .insertInto("message")
            .values({
              uri: evt.uri.toString(),
              authorDid: evt.did,
              message: record.message,
              createdAt: record.createdAt,
              indexedAt: now.toISOString(),
            })
            .onConflict((oc) =>
              oc.column("uri").doUpdateSet({
                message: record.message,
                indexedAt: now.toISOString(),
              }),
            )
            .execute();
        } else if (
          evt.collection === "xyz.statusphere.private.key" &&
          KeyPackage.isRecord(record) &&
          KeyPackage.validateRecord(record).success
        ) {
          // Store the status in our SQLite
          await db
            .insertInto("key_package")
            .values({
              uri: evt.uri.toString(),
              authorDid: evt.did,
              package: record.package,
              createdAt: record.createdAt,
              indexedAt: now.toISOString(),
            })
            .onConflict((oc) =>
              oc.column("uri").doUpdateSet({
                package: record.package,
                indexedAt: now.toISOString(),
              }),
            )
            .execute();
        }
      } else if (evt.event === "delete") {
        if (evt.collection === "xyz.statusphere.private.status") {
          // Remove the status from our SQLite
          await db
            .deleteFrom("status")
            .where("uri", "=", evt.uri.toString())
            .execute();
        } else if (evt.collection === "xyz.statusphere.private.key") {
          // Remove the status from our SQLite
          await db
            .deleteFrom("key_package")
            .where("uri", "=", evt.uri.toString())
            .execute();
        } else if (evt.collection === "xyz.statusphere.private.message") {
          // Remove the status from our SQLite
          await db
            .deleteFrom("message")
            .where("uri", "=", evt.uri.toString())
            .execute();
        }
      }
    },
    onError: (err) => {
      logger.error({ err }, "error on firehose ingestion");
    },
    filterCollections: ["xyz.statusphere.private.status"],
    excludeIdentity: true,
    excludeAccount: true,
  });
}

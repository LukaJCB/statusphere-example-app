/**
 * GENERATED CODE - DO NOT MODIFY
 */
import { ValidationResult, BlobRef } from "@atproto/lexicon";
import { lexicons } from "../../../../lexicons";
import { isObj, hasProp } from "../../../../util";
import { CID } from "multiformats/cid";

export interface Record {
  package: string;
  createdAt: string;
  [k: string]: unknown;
}

export function isRecord(v: unknown): v is Record {
  return (
    isObj(v) &&
    hasProp(v, "$type") &&
    (v.$type === "xyz.statusphere.private.key#main" ||
      v.$type === "xyz.statusphere.private.key")
  );
}

export function validateRecord(v: unknown): ValidationResult {
  return lexicons.validate("xyz.statusphere.private.key#main", v);
}

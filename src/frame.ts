import { SecureMessagingProtocolError } from "./errors";
import {
  SECURE_MESSAGING_FRAME_CONTRACT,
  type SecureMessagingFrame,
} from "./types";

type WireFrame = {
  authenticatedContext: {
    conversationId: string;
    expiresAt?: number;
    purpose: string;
    securityEpoch: number;
    senderId: string;
  };
  contract: number;
  createdAt: number;
  expiresAt: number;
  id: string;
  protectedBytes: string;
  protocol: string;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hasExactKeys = (
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean => {
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  return (
    required.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => allowed.has(key))
  );
};

const isSafeTimestamp = (value: unknown): value is number =>
  Number.isSafeInteger(value) && Number(value) >= 0;

const isNonEmpty = (value: unknown, maximum: number): value is string =>
  typeof value === "string" && value.length > 0 && value.length <= maximum;

const encodeBase64url = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
};

const decodeBase64url = (value: string): Uint8Array => {
  if (!/^[A-Za-z0-9_-]*$/.test(value))
    throw new SecureMessagingProtocolError(
      "Frame ciphertext is not base64url.",
    );
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
  } catch {
    throw new SecureMessagingProtocolError(
      "Frame ciphertext is not base64url.",
    );
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

export const encodeSecureMessagingFrame = (
  frame: SecureMessagingFrame,
): Uint8Array => {
  validateSecureMessagingFrame(frame);
  const wire: WireFrame = {
    authenticatedContext: { ...frame.authenticatedContext },
    contract: frame.contract,
    createdAt: frame.createdAt,
    expiresAt: frame.expiresAt,
    id: frame.id,
    protectedBytes: encodeBase64url(frame.protectedBytes),
    protocol: frame.protocol,
  };
  return encoder.encode(JSON.stringify(wire));
};

export const decodeSecureMessagingFrame = (
  bytes: Uint8Array,
): SecureMessagingFrame => {
  let value: unknown;
  try {
    value = JSON.parse(decoder.decode(bytes));
  } catch {
    throw new SecureMessagingProtocolError(
      "Secure messaging frame is invalid JSON.",
    );
  }
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "authenticatedContext",
      "contract",
      "createdAt",
      "expiresAt",
      "id",
      "protectedBytes",
      "protocol",
    ]) ||
    !isRecord(value.authenticatedContext) ||
    !hasExactKeys(
      value.authenticatedContext,
      ["conversationId", "purpose", "securityEpoch", "senderId"],
      ["expiresAt"],
    ) ||
    typeof value.protectedBytes !== "string"
  )
    throw new SecureMessagingProtocolError(
      "Secure messaging frame shape is invalid.",
    );
  const frame: SecureMessagingFrame = {
    authenticatedContext: {
      conversationId: value.authenticatedContext.conversationId as string,
      ...(value.authenticatedContext.expiresAt === undefined
        ? {}
        : { expiresAt: value.authenticatedContext.expiresAt as number }),
      purpose: value.authenticatedContext.purpose as string,
      securityEpoch: value.authenticatedContext.securityEpoch as number,
      senderId: value.authenticatedContext.senderId as string,
    },
    contract: value.contract as 1,
    createdAt: value.createdAt as number,
    expiresAt: value.expiresAt as number,
    id: value.id as string,
    protectedBytes: decodeBase64url(value.protectedBytes),
    protocol: value.protocol as string,
  };
  validateSecureMessagingFrame(frame);
  return Object.freeze({
    ...frame,
    authenticatedContext: Object.freeze({ ...frame.authenticatedContext }),
    protectedBytes: frame.protectedBytes.slice(),
  });
};

export const validateSecureMessagingFrame = (
  frame: SecureMessagingFrame,
): void => {
  const context = frame.authenticatedContext;
  if (
    frame.contract !== SECURE_MESSAGING_FRAME_CONTRACT ||
    !idPattern.test(frame.id) ||
    !isSafeTimestamp(frame.createdAt) ||
    !isSafeTimestamp(frame.expiresAt) ||
    frame.expiresAt <= frame.createdAt ||
    !isNonEmpty(frame.protocol, 128) ||
    frame.protectedBytes.length === 0 ||
    !isNonEmpty(context.conversationId, 256) ||
    !isNonEmpty(context.purpose, 256) ||
    !isNonEmpty(context.senderId, 256) ||
    !Number.isSafeInteger(context.securityEpoch) ||
    context.securityEpoch < 0 ||
    (context.expiresAt !== undefined &&
      (!isSafeTimestamp(context.expiresAt) ||
        context.expiresAt !== frame.expiresAt))
  )
    throw new SecureMessagingProtocolError(
      "Secure messaging frame values are invalid.",
    );
};

import { describe, expect, test } from "bun:test";
import {
  decodeSecureMessagingFrame,
  encodeSecureMessagingFrame,
  SECURE_MESSAGING_FRAME_CONTRACT,
} from "../src";

const frame = {
  authenticatedContext: {
    conversationId: "conversation-1",
    expiresAt: 2_000,
    purpose: "chat.message",
    securityEpoch: 3,
    senderId: "alice-phone",
  },
  contract: SECURE_MESSAGING_FRAME_CONTRACT,
  createdAt: 1_000,
  expiresAt: 2_000,
  id: "message-1",
  protectedBytes: Uint8Array.of(1, 2, 3),
  protocol: "MLS-1.0",
} as const;

describe("secure messaging frame", () => {
  test("round-trips authenticated metadata and opaque ciphertext", () => {
    expect(
      decodeSecureMessagingFrame(encodeSecureMessagingFrame(frame)),
    ).toEqual(frame);
  });

  test("rejects extension smuggling and expiry substitution", () => {
    const encoded = JSON.parse(
      new TextDecoder().decode(encodeSecureMessagingFrame(frame)),
    ) as Record<string, unknown>;
    expect(() =>
      decodeSecureMessagingFrame(
        new TextEncoder().encode(JSON.stringify({ ...encoded, admin: true })),
      ),
    ).toThrow("shape");
    expect(() =>
      encodeSecureMessagingFrame({
        ...frame,
        authenticatedContext: {
          ...frame.authenticatedContext,
          expiresAt: 2_001,
        },
      }),
    ).toThrow("values");
  });

  test("rejects malformed base64url and empty ciphertext", () => {
    const encoded = JSON.parse(
      new TextDecoder().decode(encodeSecureMessagingFrame(frame)),
    ) as Record<string, unknown>;
    expect(() =>
      decodeSecureMessagingFrame(
        new TextEncoder().encode(
          JSON.stringify({ ...encoded, protectedBytes: "+invalid" }),
        ),
      ),
    ).toThrow("base64url");
    expect(() =>
      encodeSecureMessagingFrame({
        ...frame,
        protectedBytes: new Uint8Array(),
      }),
    ).toThrow("values");
  });
});

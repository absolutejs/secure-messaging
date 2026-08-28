import { expect, test } from "bun:test";
import {
  SecureMessagingDurabilityUncertainError,
  SecureMessagingError,
} from "../src";

test("durability uncertainty is typed without embedding operation data", () => {
  const cause = new Error("private provider diagnostic");
  const error = new SecureMessagingDurabilityUncertainError({ cause });

  expect(error).toBeInstanceOf(SecureMessagingError);
  expect(error.name).toBe("SecureMessagingDurabilityUncertainError");
  expect(error.outcome).toBe("unknown");
  expect(error.message).toBe(
    "Secure messaging durability acknowledgement was not confirmed. Reload authoritative store state before retrying.",
  );
  expect(error.cause).toBe(cause);
  expect(Object.keys(error)).not.toContain("conversationId");
});

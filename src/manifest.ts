import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<{
  maximumFrameBytes?: number;
  maximumFutureSkewMs?: number;
  maximumMessageBytes?: number;
  maximumTtlMs?: number;
}>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams", "agent-hosts"],
    intents: [
      "orchestrate an end-to-end encrypted conversation",
      "invite a verified device with a mode-bound MLS Welcome",
      "hold or reject an unsolicited encrypted-group invitation",
      "remove a device and rotate MLS group secrets",
      "self-update an MLS member leaf",
      "replace lost devices with an authority-approved recovery grant",
      "send an expiring authenticated message",
      "bind a sensitive application message to an expected MLS epoch",
      "detect replayed secure messages",
      "retry delivery without losing advanced group state",
      "use an untrusted delivery service safely",
    ],
    keywords: [
      "secure messaging",
      "E2EE",
      "MLS",
      "replay protection",
      "authenticated context",
      "untrusted delivery",
    ],
    protocols: ["RFC 9420 MLS"],
  },
  identity: {
    accent: "#2563eb",
    category: "security",
    description:
      "Provider-neutral secure conversation orchestration with explicit confidentiality modes, authenticated framing, replay defense, expiry, and policy gates.",
    docsUrl: "https://github.com/absolutejs/secure-messaging",
    name: "@absolutejs/secure-messaging",
    tagline: "Compose secure conversations without trusting the transport.",
  },
  settings: Type.Object(
    {
      maximumFrameBytes: Type.Optional(
        Type.Integer({
          default: 1572864,
          description: "Maximum encoded frame size accepted before parsing.",
          minimum: 1,
          title: "Maximum frame bytes",
        }),
      ),
      maximumFutureSkewMs: Type.Optional(
        Type.Integer({
          default: 300000,
          description: "Maximum accepted sender clock lead for inbound frames.",
          minimum: 0,
          title: "Maximum future clock skew",
        }),
      ),
      maximumMessageBytes: Type.Optional(
        Type.Integer({
          default: 1048576,
          description: "Maximum plaintext message size accepted by policy.",
          minimum: 1,
          title: "Maximum message bytes",
        }),
      ),
      maximumTtlMs: Type.Optional(
        Type.Integer({
          default: 86400000,
          description: "Maximum lifetime of an authenticated message frame.",
          minimum: 1,
          title: "Maximum message lifetime",
        }),
      ),
    },
    { additionalProperties: false },
  ),
  wiring: [],
});

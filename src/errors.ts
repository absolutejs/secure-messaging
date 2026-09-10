export class SecureMessagingError extends Error {
  override readonly name: string = "SecureMessagingError";
}

export class SecureMessagingConfigurationError extends SecureMessagingError {
  override readonly name = "SecureMessagingConfigurationError";
}

export class SecureMessagingProtocolError extends SecureMessagingError {
  override readonly name = "SecureMessagingProtocolError";
}

export class SecureMessagingDurabilityUncertainError extends SecureMessagingError {
  override readonly name = "SecureMessagingDurabilityUncertainError";
  readonly outcome = "unknown" as const;

  constructor(options?: ErrorOptions) {
    super(
      "Secure messaging durability acknowledgement was not confirmed. Reload authoritative store state before retrying.",
      options,
    );
  }
}

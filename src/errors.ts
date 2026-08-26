export class SecureMessagingError extends Error {
  override readonly name: string = "SecureMessagingError";
}

export class SecureMessagingConfigurationError extends SecureMessagingError {
  override readonly name = "SecureMessagingConfigurationError";
}

export class SecureMessagingProtocolError extends SecureMessagingError {
  override readonly name = "SecureMessagingProtocolError";
}

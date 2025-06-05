package com.google.apigee.callouts.wsseccrypto;

public enum EncryptedKeyLocation {
  NOT_SPECIFIED,
  IN_SECURITY_HEADER,
  UNDER_ENCRYPTED_DATA;

  static EncryptedKeyLocation fromString(String s) {
    for (EncryptedKeyLocation t : EncryptedKeyLocation.values()) {
      if (t.name().equals(s)) return t;
    }
    return EncryptedKeyLocation.NOT_SPECIFIED;
  }
}

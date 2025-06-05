package com.google.apigee.callouts.wsseccrypto;

public enum KeyIdentifierType {
  NOT_SPECIFIED,
  THUMBPRINT,
  X509_CERT_DIRECT,
  BST_DIRECT_REFERENCE,
  RSA_KEY_VALUE,
  ISSUER_SERIAL;

  static KeyIdentifierType fromString(String s) {
    for (KeyIdentifierType t : KeyIdentifierType.values()) {
      if (t.name().equals(s)) return t;
    }
    return KeyIdentifierType.NOT_SPECIFIED;
  }
}

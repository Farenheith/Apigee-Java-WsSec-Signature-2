package com.google.apigee.callouts.wsseccrypto;

public enum RsaAlgorithm {
  NOT_SPECIFIED,
  PKCS1_5,
  OAEP,
  OAEP1_1;

  static RsaAlgorithm fromString(String s) {
    for (RsaAlgorithm t : RsaAlgorithm.values()) {
      if (t.name().equals(s)) return t;
    }
    return RsaAlgorithm.NOT_SPECIFIED;
  }

  public String asUriString() {
      switch (this) {
        case PKCS1_5:
          return "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
        case OAEP:
          return "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
      }
      return "none";
  }

}

package com.google.apigee.callouts.wsseccrypto;

import java.util.Optional;
import org.apache.xml.security.encryption.XMLCipher;

public enum ContentEncryptionCipher {
  NOT_SPECIFIED,
  AES_128_CBC, AES_192_CBC, AES_256_CBC,
  AES_128_GCM, AES_192_GCM, AES_256_GCM,
  TRIPLEDES;

  public static Optional<ContentEncryptionCipher> getValueOf(String name) {
    try {
        return Optional.of(Enum.valueOf(ContentEncryptionCipher.class, name));
    } catch(IllegalArgumentException ex) {
        return Optional.empty();
    }
  }

  public int getSymmetricKeyLength() {
      switch (this) {
        case AES_128_GCM:
        case AES_128_CBC: return 128;

        case AES_192_GCM:
        case AES_192_CBC: return 192;

        case AES_256_GCM:
        case AES_256_CBC: return 256;

        case TRIPLEDES: return 192;
      }
      throw new IllegalArgumentException();
  }

  public String asXmlCipherString() {
      switch (this) {
        case AES_128_CBC:
          return XMLCipher.AES_128;

        case AES_128_GCM:
          return XMLCipher.AES_128_GCM;

        case AES_192_CBC:
          return XMLCipher.AES_192;

        case AES_192_GCM:
          return XMLCipher.AES_192_GCM;

        case AES_256_CBC:
          return XMLCipher.AES_256;

        case AES_256_GCM:
          return XMLCipher.AES_256_GCM;

        case TRIPLEDES:
          return XMLCipher.TRIPLEDES;
      }
      throw new IllegalArgumentException();
  }
}

// Copyright 2018-2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callouts.wsseccrypto;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.xml.Namespaces;
import java.io.IOException;
import java.io.StringReader;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class Decrypt extends WssecCalloutBase implements Execution {
  private static final int PEM_LINE_LENGTH = 64;

  public Decrypt(Map properties) {
    super(properties);
  }

  private static class DocumentEncryptionState {
    public String soapns;
    public String keyEncryptionAlgorithm;
    public String contentEncryptionAlgorithm;
    public Element encryptedKeyElement;
    public Element encryptedDataElement;
  }

  private static DocumentEncryptionState checkCompulsoryElements(
      Document doc, DecryptConfiguration configuration) {
    NodeList nl = null;
    DocumentEncryptionState state = new DocumentEncryptionState();
    state.soapns =
        (configuration.soapVersion.equals("soap1.2")) ? Namespaces.SOAP1_2 : Namespaces.SOAP1_1;

    nl = doc.getElementsByTagNameNS(state.soapns, "Envelope");
    if (nl.getLength() == 0) throw new IllegalStateException("no Envelope");
    if (nl.getLength() != 1) throw new IllegalStateException("more than one Envelope");

    Element envelope = (Element) nl.item(0);

    nl = envelope.getElementsByTagNameNS(state.soapns, "Header");
    if (nl.getLength() == 0) throw new IllegalStateException("no Header");
    if (nl.getLength() != 1) throw new IllegalStateException("more than one Header");
    Element header = (Element) nl.item(0);

    nl = header.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
    if (nl.getLength() == 0) throw new IllegalStateException("no Security");
    if (nl.getLength() != 1) throw new IllegalStateException("more than one Security");
    Element security = (Element) nl.item(0);

    nl = envelope.getElementsByTagNameNS(state.soapns, "Body");
    if (nl.getLength() == 0) throw new IllegalStateException("no Body");
    if (nl.getLength() != 1) throw new IllegalStateException("more than one Body");
    Element body = (Element) nl.item(0);

    nl = body.getElementsByTagNameNS(Namespaces.XMLENC, "EncryptedData");
    if (nl.getLength() == 0) throw new IllegalStateException("no EncryptedData");
    if (nl.getLength() != 1) throw new IllegalStateException("more than one EncryptedData");
    Element encryptedData = (Element) nl.item(0);
    state.encryptedDataElement = encryptedData;

    nl = encryptedData.getElementsByTagNameNS(Namespaces.XMLENC, "EncryptedKey");
    if (nl.getLength() == 0) {
      // EncryptedKey may be a child of wssec:Security
      nl = security.getElementsByTagNameNS(Namespaces.XMLENC, "EncryptedKey");
      if (nl.getLength() == 0) throw new IllegalStateException("no EncryptedKey");
    }

    if (nl.getLength() != 1) throw new IllegalStateException("more than one EncryptedKey");

    Element encryptedKey = (Element) nl.item(0);
    state.encryptedKeyElement = encryptedKey;

    nl = encryptedKey.getElementsByTagNameNS(Namespaces.XMLENC, "EncryptionMethod");
    if (nl.getLength() == 0) throw new IllegalStateException("no EncryptedKey/EncryptionMethod");
    if (nl.getLength() != 1)
      throw new IllegalStateException("more than one EncryptedKey/EncryptionMethod");
    Element encryptionMethod = (Element) nl.item(0);
    String methodAlgorithm = encryptionMethod.getAttribute("Algorithm");

    state.keyEncryptionAlgorithm = methodAlgorithm;

    if (!methodAlgorithm.equals("http://www.w3.org/2001/04/xmlenc#rsa-1_5")
        && !methodAlgorithm.equals("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"))
      throw new IllegalStateException("unsupported EncryptionMethod for EncryptedKey");

    encryptionMethod =
        getChildElementsByTagNameNS(encryptedData, Namespaces.XMLENC, "EncryptionMethod");

    if (encryptionMethod == null)
      throw new IllegalStateException("no EncryptedData/EncryptionMethod");

    state.contentEncryptionAlgorithm = encryptionMethod.getAttribute("Algorithm");

    return state;
  }

  private Document decrypt_RSA(Document doc, DecryptConfiguration configuration) throws Exception {
    DocumentEncryptionState state = checkCompulsoryElements(doc, configuration);
    if (configuration.contentEncryptionCipher != ContentEncryptionCipher.NOT_SPECIFIED) {
      if (!state.contentEncryptionAlgorithm.equals(
          configuration.contentEncryptionCipher.asXmlCipherString()))
        throw new IllegalStateException("unacceptable Content EncryptionMethod");
    }

    if (configuration.rsaAlgorithm != RsaAlgorithm.NOT_SPECIFIED) {
      if (!state.keyEncryptionAlgorithm.equals(
          configuration.rsaAlgorithm.asUriString()))
        throw new IllegalStateException("unacceptable Key EncryptionMethod");
    }

    // this works regardless where the EncryptedKey is found
    XMLCipher xmlCipher = XMLCipher.getInstance();
    xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
    EncryptedData encryptedData = xmlCipher.loadEncryptedData(doc, state.encryptedDataElement);
    EncryptedKey encryptedKey = xmlCipher.loadEncryptedKey(doc, state.encryptedKeyElement);

    if (encryptedData == null || encryptedKey == null)
      throw new IllegalStateException("Not a valid encrypted document");

    String encAlgoURL = encryptedData.getEncryptionMethod().getAlgorithm();
    XMLCipher keyCipher = XMLCipher.getInstance();
    keyCipher.init(XMLCipher.UNWRAP_MODE, configuration.privateKey);
    Key encryptionKey = keyCipher.decryptKey(encryptedKey, encAlgoURL);
    xmlCipher = XMLCipher.getInstance();
    xmlCipher.init(XMLCipher.DECRYPT_MODE, encryptionKey);

    xmlCipher.doFinal(doc, state.encryptedDataElement, false); // ??
    return doc;
  }

  private static RSAPrivateKey readKey(String privateKeyPemString, String password)
      throws IOException, OperatorCreationException, PKCSException, InvalidKeySpecException,
          NoSuchAlgorithmException {
    if (privateKeyPemString == null) {
      throw new IllegalStateException("PEM String is null");
    }
    if (password == null) password = "";

    PEMParser pr = null;
    try {
      pr = new PEMParser(new StringReader(privateKeyPemString));
      Object o = pr.readObject();

      if (o == null) {
        throw new IllegalStateException("Parsed object is null.  Bad input.");
      }
      if (!((o instanceof PEMEncryptedKeyPair)
          || (o instanceof PKCS8EncryptedPrivateKeyInfo)
          || (o instanceof PrivateKeyInfo)
          || (o instanceof PEMKeyPair))) {
        throw new IllegalStateException(
            "Didn't find OpenSSL key. Found: " + o.getClass().getName());
      }

      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

      if (o instanceof PEMKeyPair) {
        // eg, "openssl genrsa -out keypair-rsa-2048-unencrypted.pem 2048"
        return (RSAPrivateKey) converter.getPrivateKey(((PEMKeyPair) o).getPrivateKeyInfo());
      }

      if (o instanceof PrivateKeyInfo) {
        // eg, "openssl genpkey  -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out keypair.pem"
        return (RSAPrivateKey) converter.getPrivateKey((PrivateKeyInfo) o);
      }

      if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
        // eg, "openssl genpkey -algorithm rsa -aes-128-cbc -pkeyopt rsa_keygen_bits:2048 -out
        // private-encrypted.pem"
        PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo =
            (PKCS8EncryptedPrivateKeyInfo) o;
        JceOpenSSLPKCS8DecryptorProviderBuilder decryptorProviderBuilder =
            new JceOpenSSLPKCS8DecryptorProviderBuilder();
        InputDecryptorProvider decryptorProvider =
            decryptorProviderBuilder.build(password.toCharArray());
        PrivateKeyInfo privateKeyInfo =
            pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
        return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
      }

      if (o instanceof PEMEncryptedKeyPair) {
        // eg, "openssl genrsa -aes256 -out private-encrypted-aes-256-cbc.pem 2048"
        PEMDecryptorProvider decProv =
            new JcePEMDecryptorProviderBuilder().setProvider("BC").build(password.toCharArray());
        KeyPair keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) o).decryptKeyPair(decProv));
        return (RSAPrivateKey) keyPair.getPrivate();
      }
    } finally {
      if (pr != null) {
        pr.close();
      }
    }
    throw new IllegalStateException("unknown PEM object");
  }

  private RSAPrivateKey getPrivateKey(MessageContext msgCtxt) throws Exception {
    String privateKeyPemString = getSimpleRequiredProperty("private-key", msgCtxt);
    privateKeyPemString = privateKeyPemString.trim();

    // clear any leading whitespace on each line
    privateKeyPemString = reformIndents(privateKeyPemString);
    String privateKeyPassword = getSimpleOptionalProperty("private-key-password", msgCtxt);
    if (privateKeyPassword == null) privateKeyPassword = "";
    return readKey(privateKeyPemString, privateKeyPassword);
  }

  static class DecryptConfiguration {
    public String soapVersion = Namespaces.SOAP1_1; // default
    public RSAPrivateKey privateKey; // required
    public X509Certificate certificate; // required
    public ContentEncryptionCipher contentEncryptionCipher =
        ContentEncryptionCipher.NOT_SPECIFIED; // optional
    public RsaAlgorithm rsaAlgorithm;

    public DecryptConfiguration() {}

    public DecryptConfiguration withSoapVersion(String version) {
      this.soapVersion = version;
      return this;
    }

    public DecryptConfiguration withPrivateKey(RSAPrivateKey privateKey) {
      this.privateKey = privateKey;
      return this;
    }

    public DecryptConfiguration withContentEncryptionCipher(ContentEncryptionCipher cipher) {
      this.contentEncryptionCipher = cipher;
      return this;
    }

    public DecryptConfiguration withRsaAlgorithm(RsaAlgorithm alg) {
      this.rsaAlgorithm = alg;
      return this;
    }
  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      msgCtxt.setVariable(varName("valid"), false);
      Document document = getDocument(msgCtxt);

      DecryptConfiguration decryptConfiguration =
          new DecryptConfiguration()
              .withSoapVersion(getSoapVersion(msgCtxt))
              .withPrivateKey(getPrivateKey(msgCtxt))
              .withRsaAlgorithm(getRsaAlgorithm(msgCtxt))
              .withContentEncryptionCipher(getContentEncryptionCipher(msgCtxt));

      Document decryptedDoc = decrypt_RSA(document, decryptConfiguration);

      msgCtxt.setVariable(varName("output"), documentToString(decryptedDoc));
      return ExecutionResult.SUCCESS;

    } catch (IllegalStateException exc1) {
      setExceptionVariables(exc1, msgCtxt);
      return ExecutionResult.ABORT;
    } catch (Exception e) {
      if (getDebug()) {
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
  }
}

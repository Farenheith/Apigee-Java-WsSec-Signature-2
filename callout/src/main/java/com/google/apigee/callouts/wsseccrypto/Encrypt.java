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
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
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

public class Encrypt extends WssecCalloutBase implements Execution {

  public Encrypt(Map properties) {
    super(properties);
  }

  private static SecretKey generateContentEncryptionKey(int keyBits)
      throws NoSuchAlgorithmException {
    KeyGenerator nonThreadSafe_AESKeyGenerator = KeyGenerator.getInstance("AES");
    nonThreadSafe_AESKeyGenerator.init(keyBits);
    return nonThreadSafe_AESKeyGenerator.generateKey();
  }

  // public static String toPrettyString(Document document, int indent) {
  //   try {
  //     // Remove whitespaces outside tags
  //     document.normalize();
  //     XPath xPath = XPathFactory.newInstance().newXPath();
  //     NodeList nodeList =
  //         (NodeList)
  //             xPath.evaluate("//text()[normalize-space()='']", document, XPathConstants.NODESET);
  //
  //     for (int i = 0; i < nodeList.getLength(); ++i) {
  //       Node node = nodeList.item(i);
  //       node.getParentNode().removeChild(node);
  //     }
  //
  //     // Setup pretty print options
  //     TransformerFactory transformerFactory = TransformerFactory.newInstance();
  //     transformerFactory.setAttribute("indent-number", indent);
  //     Transformer transformer = transformerFactory.newTransformer();
  //     transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
  //     transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
  //     transformer.setOutputProperty(OutputKeys.INDENT, "yes");
  //
  //     // Return pretty print xml string
  //     StringWriter stringWriter = new StringWriter();
  //     transformer.transform(new DOMSource(document), new StreamResult(stringWriter));
  //     return stringWriter.toString();
  //   } catch (Exception e) {
  //     throw new RuntimeException(e);
  //   }
  // }

  private int nsCounter = 1;

  private String declareXmlnsPrefix(
      Element elt, Map<String, String> knownNamespaces, String namespaceURIToAdd) {
    // search here for an existing prefix with the specified URI.
    String prefix = knownNamespaces.get(namespaceURIToAdd);
    if (prefix != null) {
      return prefix;
    }

    // find the default prefix for the specified URI.
    prefix = Namespaces.defaultPrefixes.get(namespaceURIToAdd);
    if (prefix == null) {
      prefix = "ns" + nsCounter++;
    }

    if (elt != null) {
      elt.setAttributeNS(Namespaces.XMLNS, "xmlns:" + prefix, namespaceURIToAdd);
    }
    return prefix;
  }

  private String encrypt_RSA(Document doc, CipherConfiguration cipherConfiguration)
      throws Exception {
    String soapns =
        (cipherConfiguration.soapVersion.equals("soap1.2"))
            ? Namespaces.SOAP1_2
            : Namespaces.SOAP1_1;

    NodeList nodes = doc.getElementsByTagNameNS(soapns, "Envelope");
    if (nodes.getLength() != 1) {
      throw new IllegalStateException("No soap:Envelope found");
    }
    Element envelope = (Element) nodes.item(0);

    nodes = envelope.getElementsByTagNameNS(soapns, "Body");
    if (nodes.getLength() != 1) {
      throw new IllegalStateException("No soap:Body found");
    }

    Map<String, String> knownNamespaces = Namespaces.getExistingNamespaces(envelope);
    String wsuPrefix = declareXmlnsPrefix(envelope, knownNamespaces, Namespaces.WSU);
    String soapPrefix = declareXmlnsPrefix(envelope, knownNamespaces, soapns);
    String wssePrefix = declareXmlnsPrefix(envelope, knownNamespaces, Namespaces.WSSEC);
    String xencPrefix = declareXmlnsPrefix(envelope, knownNamespaces, Namespaces.XMLENC);
    String xmldsigPrefix = declareXmlnsPrefix(envelope, knownNamespaces, Namespaces.XMLDSIG);

    String bodyId = null;
    // 1. get or set the Id of the Body element
    Element body = (Element) nodes.item(0);
    if (body.hasAttributeNS(Namespaces.WSU, "Id")) {
      bodyId = body.getAttributeNS(Namespaces.WSU, "Id");
    } else {
      bodyId = "Body-" + java.util.UUID.randomUUID().toString();
      body.setAttributeNS(Namespaces.WSU, wsuPrefix + ":Id", bodyId);
      // body.setIdAttributeNS(Namespaces.WSU, wsuPrefix + ":Id", true);
      body.setIdAttributeNS(Namespaces.WSU, "Id", true);
    }

    // 2. create or get the soap:Header
    Element header = null;
    nodes = doc.getElementsByTagNameNS(soapns, "Header");
    if (nodes.getLength() == 0) {
      header = doc.createElementNS(soapns, soapPrefix + ":Header");
      envelope.insertBefore(header, body);
    } else {
      header = (Element) nodes.item(0);
    }

    // 3. create or get the WS-Security element within the header
    Element wssecHeader = null;
    nodes = header.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
    if (nodes.getLength() == 0) {
      wssecHeader = doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":Security");
      wssecHeader.setAttributeNS(soapns, soapPrefix + ":mustUnderstand", "1");
      header.appendChild(wssecHeader);
      // envelope.insertBefore(wssecHeader, header.getFirstChild());
    } else {
      wssecHeader = (Element) nodes.item(0);
    }

    // 4. maybe embed the BinarySecurityToken under wsse:Security
    String bstId = "none";
    if (cipherConfiguration.keyIdentifierType == KeyIdentifierType.BST_DIRECT_REFERENCE) {
      Element bst = doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":BinarySecurityToken");
      bstId = "SecurityToken-" + java.util.UUID.randomUUID().toString();
      bst.setAttributeNS(Namespaces.WSU, wsuPrefix + ":Id", bstId);
      bst.setIdAttributeNS(Namespaces.WSU, "Id", true);
      bst.setAttribute(
          "EncodingType",
          "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
      bst.setAttribute(
          "ValueType",
          "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
      bst.setTextContent(
          Base64.getEncoder().encodeToString(cipherConfiguration.certificate.getEncoded()));
      wssecHeader.appendChild(bst);
    }

    // 5. create a random content encryption key (cek) and prepare the encrypted form
    if (cipherConfiguration.contentEncryptionCipher == ContentEncryptionCipher.NOT_SPECIFIED)
      cipherConfiguration.contentEncryptionCipher = ContentEncryptionCipher.AES_192_CBC;
    final String symmetricCipher = cipherConfiguration.contentEncryptionCipher.asXmlCipherString();
    Key contentEncryptingKey =
        generateContentEncryptionKey(
            cipherConfiguration.contentEncryptionCipher.getSymmetricKeyLength());
    // encrypt the cek
    RSAPublicKey certPublicKey = (RSAPublicKey) cipherConfiguration.certificate.getPublicKey();

    String cipherName =
        (cipherConfiguration.rsaAlgorithm == RsaAlgorithm.OAEP)
          ? XMLCipher.RSA_OAEP
          : XMLCipher.RSA_v1dot5;

    XMLCipher keyCipher = XMLCipher.getInstance(cipherName);
    keyCipher.init(XMLCipher.WRAP_MODE, certPublicKey);
    EncryptedKey encryptedKey = keyCipher.encryptKey(doc, contentEncryptingKey);

    KeyInfo keyInfo = new KeyInfo(doc);

    // 6. elaborate the keyinfo element
    if (cipherConfiguration.keyIdentifierType == KeyIdentifierType.BST_DIRECT_REFERENCE) {
      // <KeyInfo>
      //   <wssec:SecurityTokenReference>
      //     <wssec:Reference URI="#SecurityToken-e828bfab-bb52-4429"
      //
      // ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
      //   </wssec:SecurityTokenReference>
      // </KeyInfo>
      Element secTokenRef =
          doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":SecurityTokenReference");
      Element reference = doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":Reference");
      reference.setAttribute("URI", "#" + bstId);
      reference.setAttribute(
          "ValueType",
          "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
      secTokenRef.appendChild(reference);
      keyInfo.addUnknownElement(secTokenRef);
    } else if (cipherConfiguration.keyIdentifierType == KeyIdentifierType.THUMBPRINT) {
      // <KeyInfo>
      //   <wsse:SecurityTokenReference>
      //     <wsse:KeyIdentifier
      //
      // ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security1.1#ThumbprintSHA1">9JscCwWHk5IvR/6JLTSayTY7M=</wsse:KeyIdentifier>
      //   </wsse:SecurityTokenReference>
      // </KeyInfo>
      Element secTokenRef =
          doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":SecurityTokenReference");
      Element keyId = doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":KeyIdentifier");
      keyId.setAttribute(
          "ValueType",
          "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security1.1#ThumbprintSHA1");
      keyId.setTextContent(getThumbprintBase64(cipherConfiguration.certificate));
      secTokenRef.appendChild(keyId);
      keyInfo.addUnknownElement(secTokenRef);
    } else if (cipherConfiguration.keyIdentifierType == KeyIdentifierType.X509_CERT_DIRECT) {
      // <KeyInfo>
      //   <X509Data>
      //
      // <X509Certificate>MIICAjCCAWugAwIBAgIQwZyW5YOCXZxHg1MBV2CpvDANBgkhkiG9w0BAQnEdD9tI7IYAAoK4O+35EOzcXbvc4Kzz7BQnulQ=</X509Certificate>
      //   </X509Data>
      // </KeyInfo>
      Element x509Data = doc.createElementNS(Namespaces.XMLDSIG, "X509Data");
      Element x509Certificate = doc.createElementNS(Namespaces.XMLDSIG, "X509Certificate");
      x509Certificate.setTextContent(
          Base64.getEncoder().encodeToString(cipherConfiguration.certificate.getEncoded()));
      x509Data.appendChild(x509Certificate);
      keyInfo.addUnknownElement(x509Data);
    } else if (cipherConfiguration.keyIdentifierType == KeyIdentifierType.RSA_KEY_VALUE) {
      // <KeyInfo>
      //   <KeyValue>
      //     <RSAKeyValue>
      //       <Modulus>B6PenDyT58LjZlG6LYD27IFCh1yO+4...yCP9YNDtsLZftMLoQ==</Modulus>
      //       <Exponent>AQAB</Exponent>
      //     </RSAKeyValue>
      //   </KeyValue>
      // </KeyInfo>
      Element keyValue = doc.createElementNS(Namespaces.XMLDSIG, "KeyValue");
      Element rsaKeyValue = doc.createElementNS(Namespaces.XMLDSIG, "RSAKeyValue");
      Element modulus = doc.createElementNS(Namespaces.XMLDSIG, "Modulus");
      Element exponent = doc.createElementNS(Namespaces.XMLDSIG, "Exponent");
      final byte[] certModulus = certPublicKey.getModulus().toByteArray();
      String encodedCertModulus = Base64.getEncoder().encodeToString(certModulus);
      modulus.setTextContent(encodedCertModulus);
      final byte[] certExponent = certPublicKey.getPublicExponent().toByteArray();
      String encodedCertExponent = Base64.getEncoder().encodeToString(certExponent);
      exponent.setTextContent(encodedCertExponent);
      rsaKeyValue.appendChild(modulus);
      rsaKeyValue.appendChild(exponent);
      keyValue.appendChild(rsaKeyValue);
      keyInfo.addUnknownElement(keyValue);
    } else if (cipherConfiguration.keyIdentifierType == KeyIdentifierType.ISSUER_SERIAL) {
      // <KeyInfo>
      //   <wsse:SecurityTokenReference wsu:Id="STR-2795B41DA34FD80A771574109162615125">
      //     <X509Data>
      //       <X509IssuerSerial>
      //         <X509IssuerName>CN=creditoexpress</X509IssuerName>
      //         <X509SerialNumber>1323432320</X509SerialNumber>
      //       </X509IssuerSerial>
      //     </X509Data>
      //   </wsse:SecurityTokenReference>
      // </KeyInfo>
      Element secTokenRef =
          doc.createElementNS(Namespaces.WSSEC, wssePrefix + ":SecurityTokenReference");
      Element x509Data = doc.createElementNS(Namespaces.XMLDSIG, "X509Data");
      Element x509IssuerSerial = doc.createElementNS(Namespaces.XMLDSIG, "X509IssuerSerial");
      Element x509IssuerName = doc.createElementNS(Namespaces.XMLDSIG, "X509IssuerName");

      if (cipherConfiguration.issuerNameStyle == IssuerNameStyle.SHORT) {
        x509IssuerName.setTextContent(
            "CN=" + getCommonName(cipherConfiguration.certificate.getSubjectX500Principal()));
      } else {
        x509IssuerName.setTextContent(cipherConfiguration.certificate.getSubjectDN().getName());
      }

      Element x509SerialNumber = doc.createElementNS(Namespaces.XMLDSIG, "X509SerialNumber");
      x509SerialNumber.setTextContent(cipherConfiguration.certificate.getSerialNumber().toString());

      x509IssuerSerial.appendChild(x509IssuerName);
      x509IssuerSerial.appendChild(x509SerialNumber);
      x509Data.appendChild(x509IssuerSerial);
      secTokenRef.appendChild(x509Data);
      keyInfo.addUnknownElement(secTokenRef);
    }

    // 7. set up the encryption of the child of soap:Body with that key
    final String encryptedDataId = "Enc-1";
    XMLCipher xmlCipher = XMLCipher.getInstance(symmetricCipher);
    xmlCipher.init(XMLCipher.ENCRYPT_MODE, contentEncryptingKey);
    EncryptedData encryptedData = xmlCipher.getEncryptedData();
    encryptedData.setId(encryptedDataId);

    if (cipherConfiguration.encryptedKeyLocation == EncryptedKeyLocation.UNDER_ENCRYPTED_DATA) {
      // 8a. put the encryptedkey under KeyInfo, and that under EncryptedData
      keyInfo.add(encryptedKey);
      encryptedData.setKeyInfo(keyInfo);
    } else {
      // 8b.1 embed the KeyInfo to the EncryptedKey and attach that EncryptedKey to the header
      encryptedKey.setKeyInfo(keyInfo);
      Element encryptedKeyElement = keyCipher.martial(doc, encryptedKey);
      wssecHeader.appendChild(encryptedKeyElement);

      // 8b.2. embed ReferenceList under EncryptedKey
      Element referenceList = doc.createElementNS(Namespaces.XMLENC, xencPrefix + ":ReferenceList");
      Element dataReference = doc.createElementNS(Namespaces.XMLENC, xencPrefix + ":DataReference");
      dataReference.setAttribute("URI", "#" + encryptedDataId);
      referenceList.appendChild(dataReference);
      encryptedKeyElement.appendChild(referenceList);
    }

    // 9. do the encryption
    Element bodyChild = getFirstChildElement(body);
    /* Do the actual encryption. "false" below indicates that we want to
    encrypt the complete element and not only it's content. This replaces
    the existing element with the encrypted form. */
    xmlCipher.doFinal(doc, bodyChild, false);

    // emit the resulting document
    return documentToString(doc);
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

  private KeyIdentifierType getKeyIdentifierType(MessageContext msgCtxt) throws Exception {
    String kitString = getSimpleOptionalProperty("key-identifier-type", msgCtxt);
    if (kitString == null) return KeyIdentifierType.BST_DIRECT_REFERENCE;
    kitString = kitString.trim().toUpperCase();
    KeyIdentifierType t = KeyIdentifierType.fromString(kitString);
    if (t == KeyIdentifierType.NOT_SPECIFIED) {
      msgCtxt.setVariable(varName("warning"), "unrecognized key-identifier-type");
      return KeyIdentifierType.BST_DIRECT_REFERENCE;
    }
    return t;
  }

  private EncryptedKeyLocation getEncryptedKeyLocation(MessageContext msgCtxt) throws Exception {
    String klocString = getSimpleOptionalProperty("encrypted-key-location", msgCtxt);
    if (klocString == null) return EncryptedKeyLocation.IN_SECURITY_HEADER;
    klocString = klocString.trim().replaceAll("-", "_").toUpperCase();
    EncryptedKeyLocation location = EncryptedKeyLocation.fromString(klocString);
    if (location == EncryptedKeyLocation.NOT_SPECIFIED) {
      msgCtxt.setVariable(varName("warning"), "unrecognized encrypted-key-location");
      return EncryptedKeyLocation.IN_SECURITY_HEADER;
    }
    return location;
  }

  static class CipherConfiguration {
    public X509Certificate certificate; // required
    public String soapVersion; // optional
    public ContentEncryptionCipher contentEncryptionCipher;
    public IssuerNameStyle issuerNameStyle;
    public KeyIdentifierType keyIdentifierType;
    public EncryptedKeyLocation encryptedKeyLocation;
    public RsaAlgorithm rsaAlgorithm;

    public CipherConfiguration() {
      keyIdentifierType = KeyIdentifierType.BST_DIRECT_REFERENCE;
    }

    public CipherConfiguration withSoapVersion(String version) {
      this.soapVersion = version;
      return this;
    }

    public CipherConfiguration withKeyIdentifierType(KeyIdentifierType kit) {
      this.keyIdentifierType = kit;
      return this;
    }

    public CipherConfiguration withEncryptedKeyLocation(EncryptedKeyLocation location) {
      this.encryptedKeyLocation = location;
      return this;
    }

    public CipherConfiguration withRsaAlgorithm(RsaAlgorithm alg) {
      this.rsaAlgorithm = alg;
      return this;
    }

    public CipherConfiguration withIssuerNameStyle(IssuerNameStyle ins) {
      this.issuerNameStyle = ins;
      return this;
    }

    public CipherConfiguration withCertificate(X509Certificate certificate) {
      this.certificate = certificate;
      return this;
    }

    public CipherConfiguration withContentEncryptionCipher(ContentEncryptionCipher cipher) {
      this.contentEncryptionCipher = cipher;
      return this;
    }
  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      Document document = getDocument(msgCtxt);

      CipherConfiguration cipherConfiguration =
          new CipherConfiguration()
              .withSoapVersion(getSoapVersion(msgCtxt))
              .withCertificate(getCertificate(msgCtxt))
              .withRsaAlgorithm(getRsaAlgorithm(msgCtxt))
              .withKeyIdentifierType(getKeyIdentifierType(msgCtxt))
              .withEncryptedKeyLocation(getEncryptedKeyLocation(msgCtxt))
              .withIssuerNameStyle(getIssuerNameStyle(msgCtxt))
              .withContentEncryptionCipher(getContentEncryptionCipher(msgCtxt));

      String resultingXmlString = encrypt_RSA(document, cipherConfiguration);
      String outputVar = getOutputVar(msgCtxt);
      msgCtxt.setVariable(outputVar, resultingXmlString);
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

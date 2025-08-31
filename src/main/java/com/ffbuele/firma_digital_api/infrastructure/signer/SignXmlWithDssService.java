package com.ffbuele.firma_digital_api.infrastructure.signer;

import com.ffbuele.firma_digital_api.application.service.SignXmlService;
import com.ffbuele.firma_digital_api.domain.model.SignatureRequest;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.dataobject.DSSDataObjectFormat;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.springframework.stereotype.Service;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore.PasswordProtection;
import java.security.MessageDigest;
import java.util.*;

@Service
public class SignXmlWithDssService implements SignXmlService {

    private static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";

    static {
        try {
            Init.init();
        } catch (Exception ignored) {
        }
    }

    @Override
    public byte[] signXml(SignatureRequest request) throws Exception {
        // 1) Asegurar que el XML tenga el atributo Id/id marcado correctamente y serializarlo
        byte[] xmlWithId = ensureRootHasId(request.getXml(), "comprobante");

        // 2) Abrir token PKCS#12
        PasswordProtection passwordProtection = new PasswordProtection(request.getPassword().toCharArray());
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new ByteArrayInputStream(request.getP12()),
                passwordProtection)) {

            List<DSSPrivateKeyEntry> privateKeys = token.getKeys();
            if (privateKeys == null || privateKeys.isEmpty()) {
                throw new Exception("No se encontró clave privada en el .p12");
            }
            DSSPrivateKeyEntry privateKey = privateKeys.get(0);

            // 3) Documento a firmar (usar xml con Id marcado)
            DSSDocument toSignDocument = new InMemoryDocument(xmlWithId);

            // 4) Parámetros XAdES
            XAdESSignatureParameters parameters = new XAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
            // Forzamos SHA-1 (puedes cambiar a SHA256/SHA512 si homologación lo requiere)
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());
            parameters.setSignedInfoCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
            parameters.setXadesNamespace(new DSSNamespace(XADES_NS, "etsi"));

            // 5) DataObjectFormat (apunta a #comprobante)
            DSSDataObjectFormat dataObjectFormat = new DSSDataObjectFormat();
            dataObjectFormat.setMimeType("text/xml");
            dataObjectFormat.setObjectReference("#comprobante");
            parameters.setDataObjectFormatList(Collections.singletonList(dataObjectFormat));

            // 6) Construir reference FORZANDO URI="#comprobante"
            DSSReference dssReference = new DSSReference();
            dssReference.setUri("#comprobante");              // <-- aquí se fija la URI correctamente
            dssReference.setId("r-" + UUID.randomUUID().toString().replace("-", ""));
            dssReference.setContents(toSignDocument);

            List<DSSTransform> transforms = new ArrayList<>();
            transforms.add(new EnvelopedSignatureTransform());
            transforms.add(new CanonicalizationTransform("http://www.w3.org/2001/10/xml-exc-c14n#"));
            dssReference.setTransforms(transforms);

            parameters.setReferences(Collections.singletonList(dssReference));

            // 7) Firmar
            XAdESService service = new XAdESService(new CommonCertificateVerifier());
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
            SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            // 8) Obtener bytes firmados
            byte[] signedBytes;
            try (InputStream is = signedDocument.openStream();
                 ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int read;
                while ((read = is.read(buffer)) != -1) {
                    baos.write(buffer, 0, read);
                }
                signedBytes = baos.toByteArray();
            }

            // 9) Quitar ds:KeyValue si aparece
            byte[] cleanedBytes = removeKeyValueFromKeyInfo(signedBytes);

            // 10) Validación local del DigestValue
            String digestCheck = checkDigestMatches(cleanedBytes);
            if (digestCheck != null) {
                throw new Exception("Comprobación de digest fallida: " + digestCheck);
            }

            return cleanedBytes;
        }
    }

    // ---------------- Helpers para Id / serialización ----------------

    private byte[] ensureRootHasId(byte[] xmlBytes, String idValue) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(xmlBytes));

        Element root = doc.getDocumentElement();
        if (root == null) {
            throw new IllegalArgumentException("XML sin elemento raíz");
        }

        root.removeAttribute("Id");
        root.setAttribute("id", idValue);

        try {
            root.setIdAttribute("id", true);
        } catch (NoSuchMethodError | IllegalArgumentException ignored) {
        }

        return documentToBytes(doc);
    }

    private byte[] documentToBytes(Document doc) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(doc), new StreamResult(baos));
        return baos.toByteArray();
    }

    private byte[] removeKeyValueFromKeyInfo(byte[] signedXml) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new ByteArrayInputStream(signedXml));

            NodeList keyValues = doc.getElementsByTagNameNS(XMLDSIG_NS, "KeyValue");
            for (int i = keyValues.getLength() - 1; i >= 0; i--) {
                Node kv = keyValues.item(i);
                Node parent = kv.getParentNode();
                if (parent != null) parent.removeChild(kv);
            }

            return documentToBytes(doc);
        } catch (Exception e) {
            return signedXml;
        }
    }

    // ---------------- checkDigestMatches (aplica transforms detectados) ----------------

    private String checkDigestMatches(byte[] signedXmlBytes) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(signedXmlBytes));

            NodeList sigs = doc.getElementsByTagNameNS(XMLDSIG_NS, "Signature");
            if (sigs == null || sigs.getLength() == 0) {
                return "No se encontró ds:Signature en el XML firmado.";
            }
            Element signature = (Element) sigs.item(0);

            NodeList refs = signature.getElementsByTagNameNS(XMLDSIG_NS, "Reference");
            if (refs == null || refs.getLength() == 0) {
                return "No se encontraron ds:Reference en SignedInfo.";
            }

            Element chosenRef = null;
            for (int i = 0; i < refs.getLength(); i++) {
                Element r = (Element) refs.item(i);
                String uri = r.getAttribute("URI");
                if (uri != null && uri.equals("#comprobante")) {
                    chosenRef = r;
                    break;
                }
            }
            if (chosenRef == null) {
                chosenRef = (Element) refs.item(0);
            }

            String refUri = chosenRef.getAttribute("URI");

            Element referencedElement = null;
            if (refUri != null && refUri.startsWith("#")) {
                String frag = refUri.substring(1);
                NodeList all = doc.getElementsByTagName("*");
                for (int i = 0; i < all.getLength(); i++) {
                    Element el = (Element) all.item(i);
                    if (el.hasAttribute("id") && frag.equals(el.getAttribute("id"))) {
                        referencedElement = el;
                        break;
                    }
                }
                if (referencedElement == null) {
                    for (int i = 0; i < all.getLength(); i++) {
                        Element el = (Element) all.item(i);
                        if (el.hasAttribute("Id") && frag.equals(el.getAttribute("Id"))) {
                            referencedElement = el;
                            break;
                        }
                    }
                }
            } else {
                referencedElement = doc.getDocumentElement();
            }

            if (referencedElement == null) {
                return "No se pudo resolver la referencia '" + refUri + "' al elemento referenciado.";
            }

            NodeList transformNodes = chosenRef.getElementsByTagNameNS(XMLDSIG_NS, "Transform");
            List<String> transformAlgs = new ArrayList<>();
            for (int i = 0; i < transformNodes.getLength(); i++) {
                Element t = (Element) transformNodes.item(i);
                String alg = t.getAttribute("Algorithm");
                if (alg != null && !alg.isEmpty()) transformAlgs.add(alg);
            }

            Document newDoc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Node imported = newDoc.importNode(referencedElement, true);
            newDoc.appendChild(imported);

            if (transformAlgs.contains("http://www.w3.org/2002/06/xmldsig-filter2") ||
                    transformAlgs.contains("http://www.w3.org/2000/09/xmldsig#enveloped-signature")) {
                NodeList innerSigs = newDoc.getElementsByTagNameNS(XMLDSIG_NS, "Signature");
                for (int i = innerSigs.getLength() - 1; i >= 0; i--) {
                    Node sigNode = innerSigs.item(i);
                    sigNode.getParentNode().removeChild(sigNode);
                }
            }

            String c14nAlg;
            if (transformAlgs.contains("http://www.w3.org/2001/10/xml-exc-c14n#")) {
                c14nAlg = "http://www.w3.org/2001/10/xml-exc-c14n#";
            } else if (transformAlgs.contains("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")) {
                c14nAlg = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
            } else {
                c14nAlg = "http://www.w3.org/2001/10/xml-exc-c14n#";
            }

            Canonicalizer canon = Canonicalizer.getInstance(c14nAlg);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            canon.canonicalizeSubtree(imported, baos);
            byte[] canonicalBytes = baos.toByteArray();

            NodeList digestMethodNodes = chosenRef.getElementsByTagNameNS(XMLDSIG_NS, "DigestMethod");
            if (digestMethodNodes == null || digestMethodNodes.getLength() == 0) {
                return "No se encontró DigestMethod en la Reference.";
            }
            Element digestMethodEl = (Element) digestMethodNodes.item(0);
            String digestAlgUri = digestMethodEl.getAttribute("Algorithm");

            String javaDigestAlg = mapDigestUriToJava(digestAlgUri);
            if (javaDigestAlg == null) {
                return "DigestMethod no soportado: " + digestAlgUri;
            }

            MessageDigest md = MessageDigest.getInstance(javaDigestAlg);
            byte[] computedDigest = md.digest(canonicalBytes);
            String computedBase64 = Base64.getEncoder().encodeToString(computedDigest);

            NodeList digestValues = chosenRef.getElementsByTagNameNS(XMLDSIG_NS, "DigestValue");
            if (digestValues == null || digestValues.getLength() == 0) {
                return "No se encontró ds:DigestValue en la Reference elegida.";
            }
            String digestValueFromXml = digestValues.item(0).getTextContent().trim();

            if (computedBase64.equals(digestValueFromXml)) {
                return null;
            } else {
                return String.format("Digest mismatch. Computed=%s, SignedInfo=%s, DigestMethod=%s, Transforms=%s",
                        computedBase64, digestValueFromXml, digestAlgUri, transformAlgs.toString());
            }
        } catch (Exception ex) {
            return "Error comprobando digest: " + ex.getMessage();
        }
    }

    private String mapDigestUriToJava(String uri) {
        if (uri == null) return null;
        switch (uri) {
            case "http://www.w3.org/2000/09/xmldsig#sha1":
                return "SHA-1";
            case "http://www.w3.org/2001/04/xmlenc#sha256":
            case "http://www.w3.org/2001/04/xmlenc#sha-256":
                return "SHA-256";
            case "http://www.w3.org/2001/04/xmlenc#sha512":
            case "http://www.w3.org/2001/04/xmlenc#sha-512":
                return "SHA-512";
            default:
                return null;
        }
    }
}

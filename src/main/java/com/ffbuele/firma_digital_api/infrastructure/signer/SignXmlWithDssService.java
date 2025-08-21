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
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import java.security.KeyStore.PasswordProtection;

import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;

@Service
public class SignXmlWithDssService implements SignXmlService {

    @Override
    public byte[] signXml(SignatureRequest request) throws Exception {
        if (!tieneNodoConId(request.getXml(), "comprobante")) {
            throw new Exception("El XML no contiene un nodo con Id=\"comprobante\". No se puede firmar.");
        }

        PasswordProtection passwordProtection = new PasswordProtection(request.getPassword().toCharArray());
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new ByteArrayInputStream(request.getP12()),
                passwordProtection)) {

            List<DSSPrivateKeyEntry> privateKeys = token.getKeys();
            if (privateKeys.isEmpty()) {
                throw new Exception("No private key found in the .p12 file");
            }
            DSSPrivateKeyEntry privateKey = privateKeys.get(0);

            DSSDocument toSignDocument = new InMemoryDocument(request.getXml());

            XAdESSignatureParameters parameters = new XAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());
            parameters.setSignedInfoCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
            parameters.setXadesNamespace(new DSSNamespace("http://uri.etsi.org/01903/v1.3.2#", "etsi"));

// No definas DSSReference a mano ni uses setReferences() aquí

            DSSDataObjectFormat dataObjectFormat = new DSSDataObjectFormat();
            dataObjectFormat.setMimeType("text/xml");
// El objectReference DEBE ser "#comprobante" (el Id de tu raíz)
            dataObjectFormat.setObjectReference("#comprobante");
            parameters.setDataObjectFormatList(Collections.singletonList(dataObjectFormat));

// Proceso de firma
            XAdESService service = new XAdESService(new CommonCertificateVerifier());
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
            SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);



            try (InputStream is = signedDocument.openStream();
                 ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int read;
                while ((read = is.read(buffer)) != -1) {
                    baos.write(buffer, 0, read);
                }
                return baos.toByteArray();
            }
        }
    }

    private boolean tieneNodoConId(byte[] xml, String idBuscado) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true); // importante para firmas
        Document doc = factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
        NodeList allElements = doc.getElementsByTagName("*");
        for (int i = 0; i < allElements.getLength(); i++) {
            Element el = (Element) allElements.item(i);
            if (el.hasAttribute("Id") && idBuscado.equals(el.getAttribute("Id"))) {
                return true;
            }
        }
        return false;
    }
}

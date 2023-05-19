package ru.gov.mcx.gispz.signservice;


import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import ru.CryptoPro.JCP.JCP;
import ru.gov.mcx.gispz.signservice.sign.XmlDSignTools;
import ru.gov.mcx.gispz.signservice.sign.crypto.exceptions.SignatureProcessingException;
import ru.gov.mcx.gispz.signservice.sign.crypto.exceptions.SignatureValidationException;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Сервис подписания
 */
public class SignApplication {
    private static final SignService signService = new SignService();
    private static final String ZERNO_NS = "urn://x-artefacts-mcx-gov-ru/fgiz-zerno/api/ws/types/";
    private static final String ACTION_SIGN = "SIGN";
    private static final String ACTION_VALIDATE = "VALIDATE";

    public static void main(String[] args) throws Exception {
        Security.addProvider(new JCP());
        new XmlDSignTools();
        SignRequest signRequest = readArgs(args);

        System.out.println(signRequest.message);

        switch (signRequest.action) {
            case ACTION_SIGN -> {
                var signed = sign(signRequest);
                System.out.println(XML.xmlDocumentToString(signed));
                try (FileOutputStream output = new FileOutputStream(signRequest.filename + ".signed.xml")) {
                    XML.writeXml(signed, output);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            case ACTION_VALIDATE -> {
                checkSignature(XML.parseXML(signRequest.message));
                System.out.println("Signature is valid");
            }
            default ->
                throw new IllegalArgumentException("Недопустимое значение параметра action, возможные значения: SIGN, VALIDATE");
        }

    }

    private static SignRequest readArgs(String[] args) throws IOException {
        Map<String, String> argsMap = new HashMap<>();
        for (String arg : args) {
            String[] parts = arg.split("=");
            argsMap.put(parts[0], parts[1]);
        }
        String container = null;
        String containerType = null;
        String containerPw = null;
        String apiVersion = argsMap.get("api_version");
        if (apiVersion == null || apiVersion.isEmpty())
            apiVersion = "1.0.3";
        String action = argsMap.get("action");
        if (action == null || action.isEmpty())
            action = ACTION_SIGN;
        String message = argsMap.get("message");
        if (message == null || message.isEmpty())
            throw new IllegalArgumentException("Подписываемое/валидируемое сообщение не задано, необходимо передать параметр: message");
        if (ACTION_SIGN.equals(action)) {
            container = argsMap.get("container_name");
            containerType = argsMap.get("container_type");
            containerPw = argsMap.get("container_pw");
            if (container == null || container.isEmpty()) {
                throw new IllegalArgumentException("Наименование контейнера не задано, необходимо передать параметр: container_name");
            }
            if (containerType == null || containerType.isEmpty())
                containerType = "HDImageStore";
        }
        SignRequest signRequest = new SignRequest();
        signRequest.apiVersion = apiVersion;
        signRequest.message = new String(Files.readAllBytes(Paths.get(message)));
        signRequest.filename = message;
        signRequest.action = action;
        signRequest.containerName = container;
        signRequest.containerType = containerType;
        signRequest.containerPw = containerPw;

        return signRequest;
    }

    private static Document sign(SignRequest signRequest) {
        try {
            PrivateKey privateKey = null;
            X509Certificate certificate = null;
            if (signRequest.privateKey != null)
                privateKey = generatePrivateKey(Base64.getDecoder().decode(signRequest.privateKey));
            if (signRequest.certificate != null)
                certificate = generateCertificate(Base64.getDecoder().decode(signRequest.certificate));

            Document xml = XML.parseXML(signRequest.message);
            Element data = XML.getAttrNS("*", xml.getDocumentElement(), "Id");

            signService.setKsContainer(signRequest.containerName);
            signService.setKsContainerType(signRequest.containerType);
            signService.setKsContainerPw(signRequest.containerPw);
            signService.init();
            Element sign = signService.sign(xml, data, privateKey, certificate);

            String prefix = data.getPrefix();
            String fullElementTag = (prefix == null ? "" : prefix + ":") + "InformationSystemSignature";
            Element signatureElement = xml.createElementNS(ZERNO_NS + signRequest.apiVersion, fullElementTag);
            signatureElement.appendChild(sign);
            data.getParentNode().appendChild(signatureElement);

            return xml;
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void checkSignature(Document doc) {
        try {
            Element data = null;
            Element sign = null;
            XPath xPath = XPathFactory.newInstance().newXPath();
            NodeList nodes = (NodeList) xPath.evaluate("//*[local-name()='MessageData']", doc, XPathConstants.NODESET);
            if (nodes.getLength() > 0)
                data = (Element) nodes.item(0);

            nodes = (NodeList) xPath.evaluate("//*[local-name()='Signature']", doc, XPathConstants.NODESET);
            if (nodes.getLength() > 0)
                sign = (Element) nodes.item(0);

            signService.validateXMLDSigDetachedSignature(data, sign);
        } catch (SignatureProcessingException | XPathExpressionException | SignatureValidationException e) {
            System.out.println("Ошибка проверки подписи ");

            e.printStackTrace();
        }
    }

    private static PrivateKey generatePrivateKey(byte[] privateKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    private static X509Certificate generateCertificate(byte[] encodedCert) throws CertificateException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);
        CertificateFactory certFactory;
        certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(inputStream);
    }

    /**
     * Класс для запроса к сервису подписания
     */
    static class SignRequest {
        /**
         * Обрабатываемое сообщение
         */
        public String message;
        /**
         * Путь к обрабатываемому файлу
         */
        public String filename;
        /**
         * Действие
         * подпись (SIGN), валидация (VALIDATE)
         */
        public String action;
        /**
         * Наименование контейнера
         */
        public String containerName;
        /**
         * Тип контейнера
         */
        public String containerType;
        /**
         * Пароль контейнера
         */
        public String containerPw;
        /**
         * Приватный ключ
         */
        public String privateKey;
        /**
         * Сертификат
         */
        public String certificate;
        /**
         * Версия АПИ
         */
        public String apiVersion;

        public SignRequest() {
        }
    }
}
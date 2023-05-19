package ru.gov.mcx.gispz.signservice;


import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.*;
import ru.CryptoPro.JCP.tools.LicenseException;
import ru.gov.mcx.gispz.signservice.sign.SignatureNamespaceContext;
import ru.gov.mcx.gispz.signservice.sign.SmevTransformSpi;
import ru.gov.mcx.gispz.signservice.sign.crypto.exceptions.DocumentIsNotSignedException;
import ru.gov.mcx.gispz.signservice.sign.crypto.exceptions.SignatureProcessingException;
import ru.gov.mcx.gispz.signservice.sign.crypto.exceptions.SignatureValidationException;
import ru.gov.mcx.gispz.signservice.sign.cryptopro.KeystoreUtil;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Класс реализующий подписание
 */
public class SignService {
    /**
     * Константа, текст ошибки проверки ЭП
     */
    public static final String EDS_ERROR_SIGNATURE_INVALID = "Ошибка проверки ЭП: Нарушена целостность ЭП";
    /**
     * Пространство имён идентифицирующее GOST R 34.11-2012 algorithm with 256-bit key
     */
    public static final String DIGEST_METHOD = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
    /**
     * Пространство имён идентифицирующее GOST R 34.10-2012 algorithm with 256-bit key
     */
    public static final String XMLDSIG_SIGN_METHOD = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";
    /**
     * Преобразование канонизации, но пространства имен с префиксом "dsig"
     */
    public static final String XMLDSIG_DETACHED_TRANSFORM_METHOD = Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS;
    /**
     * Пространство имён xmldsig
     */
    public static final String XMLDSIG_ENVELOPED_TRANSFORM_METHOD = Transforms.TRANSFORM_ENVELOPED_SIGNATURE;
    /**
     * Пространство имён WSSecurity
     */
    public static final String WSSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";


    private static final ThreadLocal<DocumentBuilder> documentBuilder = ThreadLocal.withInitial(() -> {
        DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
        domFactory.setNamespaceAware(true);
        try {
            return domFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }
    });


    private String ksContainer;
    private String ksContainerType;
    private String ksContainerPw;

    private X509Certificate certificate;

    private PrivateKey privateKey;

    public SignService() {
    }

    /**
     * Инициализация ключей из контейнера
     */
    public void init() {
        if (certificate != null && privateKey != null)
            return;
        try {
            this.certificate = KeystoreUtil.getCertificateFromKeystore(ksContainerType, ksContainer);

            this.privateKey = KeystoreUtil.getPrivateKeyFromKeystore(ksContainerType, ksContainer, ksContainerPw == null ? "" : ksContainerPw);
        }
        catch (LicenseException e) {
            System.out.println("License has expired");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Подпись элемента
     * @param doc - исходный документ
     * @param element2Sign - элемент, который необходимо подписать
     * @param privateKey - приватный ключ
     * @param certificate - сертификат
     * @return - подписаный документ
     * @throws SignatureProcessingException
     */
    protected Element sign(Document doc, Element element2Sign, PrivateKey privateKey, X509Certificate certificate) throws SignatureProcessingException {
        Element signature = signXMLDSig(doc, element2Sign, privateKey == null ? this.privateKey : privateKey, certificate == null ? this.certificate : certificate, false);
        if (signature.getOwnerDocument() == doc) {
            return signature;
        }
        else {
            return (Element) doc.importNode(signature, true);
        }
    }

    /**
     * Подпись элемента
     * @param argDocument - исходный документ
     * @param element2Sign - элемент, который необходимо подписать
     * @param argPrivateKey - приватный ключ
     * @param argCertificate - сертификат
     * @param enveloped - втроенная подпись
     * @return - подписаный элемент
     * @throws SignatureProcessingException
     */
    protected Element signXMLDSig(Document argDocument, Element element2Sign, PrivateKey argPrivateKey, X509Certificate argCertificate, boolean enveloped) throws SignatureProcessingException {
        try {
            Element _element2Sign = element2Sign != null ? element2Sign : argDocument.getDocumentElement();
            String referenceURI = _element2Sign.getAttribute("Id");
            if (referenceURI == null || "".equals(referenceURI.trim())) {
                referenceURI = _element2Sign.getAttributeNS(WSSU_NS, "Id");
            }
            if (referenceURI == null || "".equals(referenceURI.trim())) {
                referenceURI = "";
            }

            //Fix, see description https://www.cryptopro.ru/forum2/default.aspx?g=posts&t=5640.
            Attr attributeNode = _element2Sign.getAttributeNode("Id");
            if (attributeNode != null && !"".equals(attributeNode.getValue().trim())) {
                _element2Sign.setIdAttributeNode(attributeNode, true);
            }

            /* Добавление узла подписи <ds:Signature> в загруженный XML-документ */

            // инициализация объекта формирования ЭЦП в соответствии с алгоритмом ГОСТ Р 34.10-2001
            XMLSignature xmlSignature = new XMLSignature(argDocument, "", XMLDSIG_SIGN_METHOD, XMLDSIG_DETACHED_TRANSFORM_METHOD);


            /* Определение правил работы с XML-документом и добавление в узел подписи этих правил */

            // создание узла преобразований <ds:Transforms> обрабатываемого XML-документа
            Transforms transforms = new Transforms(argDocument);

            // добавление в узел преобразований правил работы с документом
            if (enveloped) {
                transforms.addTransform(XMLDSIG_ENVELOPED_TRANSFORM_METHOD);
            }
            transforms.addTransform(XMLDSIG_DETACHED_TRANSFORM_METHOD);
            transforms.addTransform(SmevTransformSpi.ALGORITHM_URN);

            // добавление в узел подписи ссылок (узла <ds:Reference>), определяющих правила работы с
            // XML-документом (обрабатывается текущий документ с заданными в узле <ds:Transforms> правилами
            // и заданным алгоритмом хеширования)
            String refURI = referenceURI;
            if (!refURI.isEmpty() && !refURI.startsWith("#")) {
                refURI = "#" + refURI;
            }
            xmlSignature.addDocument(refURI, transforms, DIGEST_METHOD);

            /* Создание подписи всего содержимого XML-документа на основе закрытого ключа, заданных правил и алгоритмов */

            // создание внутри узла подписи узла <ds:KeyInfo> информации об открытом ключе на основе
            // сертификата
            xmlSignature.addKeyInfo(argCertificate);

            // создание подписи XML-документа
            xmlSignature.sign(argPrivateKey);

            return xmlSignature.getElement();
        } catch (Exception e) {
            throw new SignatureProcessingException(e);
        }
    }

    /**
     * Валидация подписи документа
     * @param signedContent - подписаный элемент
     * @param detachedSignature - подпись
     * @return - если подпись корректная возвращается сертификат
     * @throws SignatureProcessingException
     * @throws SignatureValidationException
     */
    public X509Certificate validateXMLDSigDetachedSignature(Element signedContent, Element detachedSignature) throws SignatureProcessingException, SignatureValidationException {
        Document tmpDocContent = documentBuilder.get().newDocument();
        Element cutContent = (Element) tmpDocContent.importNode(signedContent, true);
        tmpDocContent.appendChild(cutContent);
        Attr idAttribute = cutContent.getAttributeNode("Id");
        if (idAttribute != null) {
            cutContent.setIdAttributeNode(idAttribute, true);
        }
        Document tmpDocSignature = documentBuilder.get().newDocument();
        Element cutSignature = (Element) tmpDocSignature.importNode(detachedSignature, true);
        tmpDocSignature.appendChild(cutSignature);
        try {
            return validateXMLDSig(cutContent, cutSignature);
        }
        catch (DocumentIsNotSignedException e) {
            throw new SignatureValidationException(e);
        }
    }

    /**
     * Валидация подписи документа
     * @param argSignedContent - подписаный элемент
     * @param argSignatureElement - подпись
     * @return - если подпись корректная возвращается сертификат
     * @throws SignatureValidationException
     * @throws DocumentIsNotSignedException
     */
    protected X509Certificate validateXMLDSig(Element argSignedContent, Element argSignatureElement) throws SignatureValidationException, DocumentIsNotSignedException {
        if (argSignedContent == null) {
            throw new DocumentIsNotSignedException("Подписанный XML-фрагмент не передан.");
        }

        if (argSignatureElement != null) {
            if (!SignatureNamespaceContext.XMLDSIG_NS.equals(argSignatureElement.getNamespaceURI()) || !"Signature".equals(argSignatureElement.getLocalName())) {
                throw new DocumentIsNotSignedException("Корневой элемент detached-подписи имеет полное имя, отличное от {http://www.w3.org/2000/09/xmldsig#}.Signature");
            }
        }

        try {
            Element signatureElement = argSignatureElement != null ? argSignatureElement : findSignatureElement(argSignedContent);
            if (signatureElement == null) {
                throw new DocumentIsNotSignedException("Не найден элемент {http://www.w3.org/2000/09/xmldsig#}.Signature");
            }

            NodeList nl = signatureElement.getElementsByTagNameNS(SignatureNamespaceContext.XMLDSIG_NS, "Reference");
            boolean emptyRefURI = false;
            if (nl.getLength() > 0) {
                Element ref = (Element) nl.item(0);
                Attr uri = ref.getAttributeNode("URI");
                emptyRefURI = (uri == null || "".equals(uri.getNodeValue()));
            }

            if (argSignatureElement != null && argSignedContent.getOwnerDocument() != argSignatureElement.getOwnerDocument()) {
                // Если подпись передана явным образом, и она не находится в том же DOM-дереве, что и подписанный контент,
                // нужно поместить их в общее DOM-дерево. Это нужно потому, что Santuario валидирует подпись только в общем документе с контентом.
                Document tmpDocument = documentBuilder.get().newDocument();
                Element tmpDocumentRootElement = (Element) tmpDocument.appendChild(tmpDocument.createElement("root_validator"));
                signatureElement = (Element) tmpDocumentRootElement.appendChild(tmpDocument.importNode(argSignatureElement, true));
                Element signedContent = (Element) tmpDocumentRootElement.appendChild(tmpDocument.importNode(argSignedContent, true));

                //Fix, see description https://www.cryptopro.ru/forum2/default.aspx?g=posts&t=5640.
                Attr attributeNode = signedContent.getAttributeNode("Id");
                signedContent.setIdAttributeNode(attributeNode, true);
                tmpDocument.normalizeDocument();

            } else if (argSignatureElement == null && (signatureElement.getParentNode() != argSignedContent || emptyRefURI)) {
                // Если подпись - enveloped, и подписанный контент находится не в корне XML-документа, Santuario
                // может неправильно понимать, на каком фрагменте проверять подпись.
                // Поэтому подписанный фрагмент выносим в отдельный документ.
                // При этом считаем, что подпись находится сразу под подписанным фрагментом.
                Document tmpDocument = documentBuilder.get().newDocument();
                Node importedSignatureParent = tmpDocument.importNode(signatureElement.getParentNode(), true);
                tmpDocument.appendChild(importedSignatureParent);
                tmpDocument.normalizeDocument();
                signatureElement = findSignatureElement(tmpDocument);
            }

            /* Проверка подписи XML-документа на основе информации об открытом ключе, хранящейся в XML-документе */
            // чтение сертификата из узла информации об открытом ключе
            return getCertificate(signatureElement);
        } catch (DOMException | XPathExpressionException e) {
            throw new SignatureValidationException(e);
        }
    }

    // обработка случаев, когда xmldsig пространство имён имеет префикс, отличный от ds:
    private static Element findSignatureElement(Node signedDoc) throws DocumentIsNotSignedException, DOMException, XPathExpressionException {
        // выбор из прочитанного содержимого пространства имени узла подписи <ds:Signature>
        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
        xpath.setNamespaceContext(new SignatureNamespaceContext());
        XPathExpression sigXP = xpath.compile("//ds:Signature[1]");
        Element sigElement = (Element) sigXP.evaluate(signedDoc, XPathConstants.NODE);

        if (sigElement == null) {
            throw new DocumentIsNotSignedException();
        }
        return sigElement;
    }

    private X509Certificate getCertificate(Element signatureElement) throws SignatureValidationException {
        try {
            // инициализация объекта проверки подписи
            XMLSignature signature = new XMLSignature(signatureElement, "");

            // чтение узла <ds:KeyInfo> информации об открытом ключе
            KeyInfo keyInfoFromSignature = signature.getKeyInfo();

            // чтение сертификата из узла информации об открытом ключе
            X509Certificate certificate = keyInfoFromSignature.getX509Certificate();

            // если сертификат найден, то осуществляется проверка
            // подписи на основе сертфиката
            if (certificate != null) {
                boolean signatureIsValid = signature.checkSignatureValue(certificate);
                if (!signatureIsValid) {
                    throw new SignatureValidationException(EDS_ERROR_SIGNATURE_INVALID);
                }
            }
            return certificate;
        } catch (XMLSecurityException e) {
            throw new SignatureValidationException(e);
        }
    }

    /**
     * установить значение наименование контейнера
     * @param ksContainer - наименование контейнера
     */
    public void setKsContainer(String ksContainer) {
        this.ksContainer = ksContainer;
    }

    /**
     * установить значение тип контейнера
     * @param ksContainerType - тип контейнера
     */
    public void setKsContainerType(String ksContainerType) {
        this.ksContainerType = ksContainerType;
    }

    /**
     * установить значение пароль контейнера
     * @param ksContainerPw - пароль контейнера
     */
    public void setKsContainerPw(String ksContainerPw) {
        this.ksContainerPw = ksContainerPw;
    }

    /**
     * Установить значение сертификата
     * @param certificate - сертификат
     */
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Установить значение приватного ключа
     * @param privateKey - приватный ключ
     */
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}

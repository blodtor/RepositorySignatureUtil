package ru.gov.mcx.gispz.signservice;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPathExpressionException;
import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;


/**
 * Утилитный класс для работы с XML
 *
 */
public class XML {

    /**
     * Преобразоварие DOM узла в строку
     * @param doc - узел
     * @return - строка
     */
    public static String xmlDocumentToString(Node doc) {
        try {
            StringWriter sw = new StringWriter();
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

            transformer.transform(new DOMSource(doc), new StreamResult(sw));
            return sw.toString();
        }
        catch (Exception ex) {
            throw new RuntimeException("Error converting to String", ex);
        }
    }

    /**
     * Преобразование XML документа в строку
     * @param xml - исходный документ
     * @return - преобразованный в строку документ
     * @throws TransformerException
     */
    public static String convertXmlToOneLine(String xml) throws TransformerException {
        // linearize xml
        final String xslt =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                        "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">\n" +
                        "    <xsl:output indent=\"no\"/>\n" +
                        "    <xsl:strip-space elements=\"*\"/>\n" +
                        "    <xsl:template match=\"@*|node()\">\n" +
                        "        <xsl:copy>\n" +
                        "            <xsl:apply-templates select=\"@*|node()\"/>\n" +
                        "        </xsl:copy>\n" +
                        "    </xsl:template>\n" +
                        "</xsl:stylesheet>";

        /* prepare XSLT transformer from String */
        Source xsltSource = new StreamSource(new StringReader(xslt));
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer(xsltSource);

        /* where to read the XML? */
        Source source = new StreamSource(new StringReader(xml));

        /* where to write the XML? */
        StringWriter stringWriter = new StringWriter();
        Result result = new StreamResult(stringWriter);

        /* transform XML to one line */
        transformer.transform(source, result);

        return stringWriter.toString();
    }

    /**
     * Получить элемент по аттрибуту с учетом пространства имён
     * @param namespaceURI - пространство имён
     * @param root - корневой элемент
     * @param path - путь к элементу
     * @return Element или null, если элемент не найден
     * @throws XPathExpressionException
     */
    public static Element getAttrNS(String namespaceURI, Element root, String ... path) throws XPathExpressionException {
        Element element = null;
        if (root.hasAttribute("Id"))
            return root.getAttributeNode("Id").getOwnerElement();
        else {
            int len = root.getChildNodes().getLength();
            for(int i = 0; i < len; i++) {
                element = getAttrNS(namespaceURI, (Element) root.getChildNodes().item(0), path);
            }
        }
        return element;
    }

    /**
     * Преобразование строки в XML документ
     * @param xml - исходная строка
     * @return - документ
     * @throws Exception
     */
    public static Document parseXML(String xml) throws Exception {
        xml = convertXmlToOneLine(xml);

        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);

        factory.setIgnoringElementContentWhitespace(true);
        final DocumentBuilder builder = factory.newDocumentBuilder();

        return builder.parse(new ByteArrayInputStream(xml.getBytes()));
    }

    /**
     * Запись DOM документа в поток
     * @param doc
     * @param output
     * @throws TransformerException
     */
    public static void writeXml(Document doc, OutputStream output) throws TransformerException {

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(output);

        transformer.transform(source, result);

    }

}

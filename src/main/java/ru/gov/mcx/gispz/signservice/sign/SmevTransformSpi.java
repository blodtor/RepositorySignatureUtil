package ru.gov.mcx.gispz.signservice.sign;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformSpi;
import org.apache.xml.security.transforms.TransformationException;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.*;
import javax.xml.stream.events.*;
import java.io.*;
import java.util.*;


/**
 * Класс, реализующий алгоритм трансформации "urn://smev-gov-ru/xmldsig/transform" для Apache
 * Santuario.
 *
 * Методические рекомендации по работе с ЕСМЭВ версия 3.4.0.3
 * https://smev3.gosuslugi.ru/portal/
 *
 * @author dpryakhin с редакциями VBurmistrov
 *
 * (https://github.com/MaksimOK/smev3cxf/blob/master/client_1.11/crypto/src/main/java/ru/
 * vo
 * skhod/crypto/impl/SmevTransformSpi.java)
 */
public class SmevTransformSpi extends TransformSpi {

    private static final String NS_PREFIX = "ns";
    public static final String ALGORITHM_URN = "urn://smev-gov-ru/xmldsig/transform";
    private static final String ENCODING_UTF_8 = "UTF-8";

    private static AttributeSortingComparator attributeSortingComparator =
        new AttributeSortingComparator();

    private static ThreadLocal<XMLInputFactory> inputFactory =
        new ThreadLocal<XMLInputFactory>() {

            @Override
            protected XMLInputFactory initialValue() {
                return XMLInputFactory.newInstance();
            }
        };

    private static ThreadLocal<XMLOutputFactory> outputFactory =
        new ThreadLocal<XMLOutputFactory>() {

            @Override
            protected XMLOutputFactory initialValue() {
                return XMLOutputFactory.newInstance();
            }
        };

    private static ThreadLocal<XMLEventFactory> eventFactory =
        new ThreadLocal<XMLEventFactory>() {

            @Override
            protected XMLEventFactory initialValue() {
                return XMLEventFactory.newInstance();
            }
        };


    @Override
    protected XMLSignatureInput enginePerformTransform(XMLSignatureInput input, OutputStream os, Element transformElement, String baseURI,
                                                       boolean secureValidation) throws IOException, CanonicalizationException, InvalidCanonicalizerException, TransformationException, ParserConfigurationException, SAXException {

        if (os == null)
            return enginePerformTransform(input);
        else {
            process(input.getOctetStream(), os);
            XMLSignatureInput result = new XMLSignatureInput((byte[]) null);
            result.setOutputStream(os);
            return result;
        }
    }


    @Override
    protected String engineGetURI() {
        return ALGORITHM_URN;
    }


    protected XMLSignatureInput enginePerformTransform(XMLSignatureInput argInput)
        throws IOException, CanonicalizationException,
        InvalidCanonicalizerException, TransformationException,
        ParserConfigurationException, SAXException {

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        process(argInput.getOctetStream(), result);
        byte[] postTransformData = result.toByteArray();

        return new XMLSignatureInput(postTransformData);
    }

    /**
     * Преобразование пространства имён
     * @param argSrc
     * @param argDst
     * @throws TransformationException
     */
    public void process(InputStream argSrc, OutputStream argDst) throws TransformationException {

        DebugOutputStream debugStream = null;

        Stack<List<Namespace>> prefixMappingStack = new Stack<List<Namespace>>();
        int prefixCnt = 1;
        XMLEventReader src = null;
        XMLEventWriter dst = null;
        try {
            src = inputFactory.get().createXMLEventReader(argSrc, ENCODING_UTF_8);

            dst = outputFactory.get().createXMLEventWriter(argDst, ENCODING_UTF_8);

            XMLEventFactory factory = eventFactory.get();

            while (src.hasNext()) {
                XMLEvent event = src.nextEvent();

                if (event.isCharacters()) {
                    String data = event.asCharacters().getData();
                    // Отсекаем возвраты каретки и пробельные строки.
                    if (!data.trim().isEmpty()) {
                        dst.add(event);
                    }
                    continue;
                }
                else if (event.isStartElement()) {
                    List<Namespace> myPrefixMappings = new LinkedList<Namespace>();
                    prefixMappingStack.push(myPrefixMappings);

                    // Обработка элемента: NS prefix rewriting.
                    // N.B. Элементы в unqualified form не поддерживаются.
                    StartElement srcEvent = (StartElement) event;
                    String nsURI = srcEvent.getName().getNamespaceURI();
                    String prefix = findPrefix(nsURI, prefixMappingStack);

                    if (prefix == null) {
                        prefix = NS_PREFIX + String.valueOf(prefixCnt++);
                        myPrefixMappings.add(factory.createNamespace(prefix, nsURI));
                    }
                    StartElement dstEvent = factory.createStartElement(
                        prefix, nsURI, srcEvent.getName().getLocalPart());
                    dst.add(dstEvent);

                    // == Обработка атрибутов. Два шага: отсортировать, промэпить namespace URI.

                    Iterator<Attribute> srcAttributeIterator = srcEvent.getAttributes();
                    // Положим атрибуты в list, чтобы их можно было отсортировать.
                    List<Attribute> srcAttributeList = new LinkedList<Attribute>();
                    while (srcAttributeIterator.hasNext()) {
                        srcAttributeList.add(srcAttributeIterator.next());
                    }
                    // Сортировка атрибутов по алфавиту.
                    Collections.sort(srcAttributeList, attributeSortingComparator);

                    // Обработка префиксов. Аналогична обработке префиксов элементов,
                    // за исключением того, что у атрибут может не иметь namespace.
                    List<Attribute> dstAttributeList = new LinkedList<Attribute>();
                    for (Attribute srcAttribute : srcAttributeList) {
                        String attributeNsURI = srcAttribute.getName().getNamespaceURI();
                        String attributeLocalName = srcAttribute.getName().getLocalPart();
                        String value = srcAttribute.getValue();
                        String attributePrefix = null;
                        Attribute dstAttribute = null;
                        if (attributeNsURI != null && !"".equals(attributeNsURI)) {
                            attributePrefix = findPrefix(attributeNsURI, prefixMappingStack);
                            if (attributePrefix == null) {
                                attributePrefix = NS_PREFIX + String.valueOf(prefixCnt++);
                                myPrefixMappings.add(factory.createNamespace(
                                    attributePrefix, attributeNsURI));
                            }
                            dstAttribute = factory.createAttribute(
                                attributePrefix, attributeNsURI, attributeLocalName, value);
                        }
                        else {
                            dstAttribute = factory.createAttribute(attributeLocalName, value);
                        }
                        dstAttributeList.add(dstAttribute);
                    }

                    // Высести namespace prefix mappings для текущего элемента.
                    // Их порядок детерминирован, т.к. перед мэппингом атрибуты
                    // были отсортированы.
                    // Поэтому дополнительной сотрировки здесь не нужно.
                    for (Namespace mapping : myPrefixMappings) {
                        dst.add(mapping);
                    }

                    // Вывести атрибуты.
                    // N.B. Мы не выводим атрибуты сразу вместе с элементом, используя метод
                    // XMLEventFactory.createStartElement(prefix, nsURI, localName,
                    //   List<Namespace>, List<Attribute>),
                    // потому что при использовании этого метода порядок атрибутов
                    // в выходном документе меняется произвольным образом.
                    for (Attribute attr : dstAttributeList) {
                        dst.add(attr);
                    }

                    continue;
                }
                else if (event.isEndElement()) {
                    // Гарантируем, что empty tags запишутся в форме <a></a>, а не в форме <a/>.
                    dst.add(eventFactory.get().createSpace(""));

                    // NS prefix rewriting
                    EndElement srcEvent = (EndElement) event;
                    String nsURI = srcEvent.getName().getNamespaceURI();
                    String prefix = findPrefix(nsURI, prefixMappingStack);
                    if (prefix == null) {
                        throw new TransformationException(
                            "EndElement: prefix mapping is not found for namespace " + nsURI);
                    }

                    EndElement dstEvent = eventFactory.get().
                        createEndElement(prefix, nsURI, srcEvent.getName().getLocalPart());
                    dst.add(dstEvent);

                    prefixMappingStack.pop();

                    continue;
                }
                else if (event.isAttribute()) {
                    // Атрибуты обрабатываются в событии startElement.
                    continue;
                }

                // Остальные события (processing instructions, start document, etc.)
                // нас не интересуют.
            }
        }
        catch (XMLStreamException e) {
            Object exArgs[] = {e.getMessage()};
            e.printStackTrace();
            throw new TransformationException(
                "Can not perform transformation " + ALGORITHM_URN, exArgs, e);
        }
        finally {
            if (src != null) {
                try {
                    src.close();
                }
                catch (XMLStreamException e) {
                    System.out.println("Can not close XMLEventReader");
                    e.printStackTrace();
                }
            }
            if (dst != null) {
                try {
                    dst.close();
                }
                catch (XMLStreamException e) {
                    System.out.println("Can not close XMLEventWriter");
                    e.printStackTrace();
                }
            }
            try {
                argSrc.close();
            }
            catch (IOException e) {
                System.out.println("Can not close input stream.");
                e.printStackTrace();
            }
            try {
                argDst.close();
            }
            catch (IOException e) {
                System.out.println("Can not close output stream.");
                e.printStackTrace();
            }
        }
    }


    private String findPrefix(String argNamespaceURI, Stack<List<Namespace>> argMappingStack) {
        if (argNamespaceURI == null) {
            throw new IllegalArgumentException("No namespace элементы не поддерживаются.");
        }

        for (List<Namespace> elementMappingList : argMappingStack) {
            for (Namespace mapping : elementMappingList) {
                if (argNamespaceURI.equals(mapping.getNamespaceURI())) {
                    return mapping.getPrefix();
                }
            }
        }
        return null;
    }


    private static class AttributeSortingComparator implements Comparator<Attribute> {

        @Override
        public int compare(Attribute x, Attribute y) {
            String xNS = x.getName().getNamespaceURI();
            String xLocal = x.getName().getLocalPart();
            String yNS = y.getName().getNamespaceURI();
            String yLocal = y.getName().getLocalPart();

            // Сначала сравниваем namespaces.
            if (xNS == null || xNS.equals("")) {
                if (yNS != null && !"".equals(xNS)) {
                    return 1;
                }
            }
            else {
                if (yNS == null || "".equals(yNS)) {
                    return -1;
                }
                else {
                    int nsComparisonResult = xNS.compareTo(yNS);
                    if (nsComparisonResult != 0) {
                        return nsComparisonResult;
                    }
                }
            }

            // Если namespaces признаны эквивалентными, сравниваем local names.
            return xLocal.compareTo(yLocal);
        }
    }


    private static class DebugOutputStream extends OutputStream {

        private ByteArrayOutputStream collector = new ByteArrayOutputStream();
        private OutputStream wrappedStream;


        public DebugOutputStream(OutputStream arg) {
            wrappedStream = arg;
        }


        public byte[] getCollectedData() {
            try {
                collector.flush();
            }
            catch (IOException e) {
            }
            return collector.toByteArray();
        }


        @Override
        public void write(int b) throws IOException {
            collector.write(b);
            wrappedStream.write(b);
        }


        @Override
        public void close() throws IOException {
            collector.close();
            wrappedStream.close();
            super.close();
        }


        @Override
        public void flush() throws IOException {
            collector.flush();
            wrappedStream.flush();
        }

    }

}

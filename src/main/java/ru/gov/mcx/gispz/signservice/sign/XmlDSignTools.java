package ru.gov.mcx.gispz.signservice.sign;

import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.transforms.InvalidTransformException;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.utils.XMLUtils;
import ru.CryptoPro.JCPxml.XmlInit;

import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;


/**
 * Класс инициализирующий Apache Santurio
 */
public class XmlDSignTools {

    public XmlDSignTools() {
        try {
            org.apache.xml.security.Init.init();
            XmlInit.init();
            Transform.register(SmevTransformSpi.ALGORITHM_URN, SmevTransformSpi.class.getCanonicalName());
            santuarioIgnoreLineBreaks(true);
            System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        }
        catch (AlgorithmAlreadyRegisteredException | ClassNotFoundException | InvalidTransformException e) {
            e.printStackTrace();
        }

    }


    private void santuarioIgnoreLineBreaks(Boolean mode) {
        final String IGNORE_LINE_BREAKS_FIELD = "ignoreLineBreaks";
        try {
            Boolean currMode = mode;
            AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {

                public Boolean run() throws Exception {
                    Field f = XMLUtils.class.getDeclaredField(IGNORE_LINE_BREAKS_FIELD);
                    f.setAccessible(true);
                    f.set(null, currMode);
                    return false;
                }
            });

        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}



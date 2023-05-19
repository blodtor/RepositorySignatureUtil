
package ru.gov.mcx.gispz.signservice.sign.cryptopro;


import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class KeyFileProcessor {

    /**
     * @param path
     * @return
     * @throws IOException
     * @throws CertificateException
     */
    public static X509Certificate getFullCertificate(String path) throws IOException, CertificateException {
        X509Certificate cert;
        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            FileInputStream is = new FileInputStream(path);
            cert = (X509Certificate) fact.generateCertificate(is);
        } catch (IOException ex) {
            throw ex;
        } catch (CertificateException ce) {
            throw ce;
        }
        return cert;
    }

    /**
     * @param path
     * @return
     * @throws Exception
     */
    public static String getPEMFile(String path, boolean keepHeader) throws Exception {
        String pattern = "-----";
        StringBuffer sb = new StringBuffer();
        BufferedReader reader;
        String line = "";
        try {
            reader = new BufferedReader(new FileReader(path));
            do {
                line = reader.readLine();
                if (!keepHeader) {
                    if (line != null && !line.substring(0, pattern.length()).equals(pattern)) {
                        sb.append(line);
                    }
                } else if (line != null) {
                    sb.append(line);
                }
            } while (line != null);
            reader.close();
            return sb.toString();
        } catch (Exception ex) {
            throw ex;
        }
    }

}

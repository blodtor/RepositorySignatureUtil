package ru.gov.mcx.gispz.signservice.sign.cryptopro;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;


public class KeystoreUtil {
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";
    public final static String LINE_SEPARATOR = System.getProperty("line.separator");
    public final static String PFX_PASSWORD = " ";

    /**
     * @param path
     * @return
     * @throws Exception
     */
    private static KeyStore loadKeyStore(String path) throws Exception {
        KeyStore ks = KeyStore.getInstance("PFXSTORE", "JCSP");
        ks.load(new FileInputStream(path), PFX_PASSWORD.toCharArray());
        return ks;
    }

    /**
     * @param storeName - Имя хранилища
     * @param alias     - Имя контейнера
     * @param password  - "" - при отсутствии пароля
     * @throws Exception
     */

    public static PrivateKey getPrivateKeyFromKeystore(String storeName, String alias, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(storeName);
        keyStore.load(null, null);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        return privateKey;
    }


    /**
     * @param path
     * @param alias
     * @param password
     * @return
     * @throws Exception
     */

    public static PrivateKey getPrivateKeyFromExternalKeystore(String path, String alias, String password) throws Exception {
        KeyStore ks = loadKeyStore(path);
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
        return privateKey;
    }


    /**
     * password  - "" - при отсутствии пароля
     *
     * @param storeName - Имя хранилища
     * @param alias     - Имя контейнера
     * @throws Exception
     */
    public static X509Certificate getCertificateFromKeystore(String storeName, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(storeName);
        keyStore.load(null, null);
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        int size = keyStore.size();
        return certificate;
    }

    /**
     * @param path
     * @param alias
     * @return
     * @throws Exception
     */
    public static X509Certificate getCertificateFromExternalKeystore(String path, String alias) throws Exception {
        KeyStore ks = loadKeyStore(path);
        X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
        return certificate;
    }


    /**
     * @param path
     * @return
     * @throws Exception
     */
    public static X509Certificate getCertificateFromFile(String path) throws Exception {
        return KeyFileProcessor.getFullCertificate(path);
    }

    /**
     * @param certificate
     * @throws Exception
     */
    public static void storeCertificateAsPEM(X509Certificate certificate, String path) throws Exception {
        String pem = formatCrtFileContents(certificate);
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(pem.getBytes());
        fos.flush();
        fos.close();
    }


    /**
     * @param certificate
     * @return
     * @throws CertificateEncodingException
     */
    private static String formatCrtFileContents(X509Certificate certificate) throws Exception {
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());
        final byte[] rawCrtText = certificate.getEncoded();
        final String encodedCertText = new String(encoder.encode(rawCrtText));
        final String cert = BEGIN_CERT + LINE_SEPARATOR + encodedCertText + LINE_SEPARATOR + END_CERT;
        return cert;
    }

}

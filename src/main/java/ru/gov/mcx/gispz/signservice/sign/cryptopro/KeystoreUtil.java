package ru.gov.mcx.gispz.signservice.sign.cryptopro;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Утилиты для работы с контейнером
 */
public class KeystoreUtil {
    public final static String PFX_PASSWORD = " ";

    /**
     * Загрузка крипто хранилища
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
     * Получение приватного ключа из контейнера
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
     * Получение сертификата из крипто хранилища
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

}

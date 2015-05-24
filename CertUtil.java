

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import static utilidades.CertUtilExt.loadProvider;

/**
 *
 * @author Jorge Sainz
 */
public class CertUtil {
    
    public static Provider loadProvider(String providerClassName)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        Class providerClass = Class.forName(providerClassName);
        Provider provider = (Provider) providerClass.newInstance();
        Security.insertProviderAt(provider, 1);
        return provider;
    }
    public static void convertirJKS_BKS(String jks, String bks, String passwd, Boolean reverse)
            throws ClassNotFoundException,
            IllegalAccessException,
            InstantiationException,
            KeyStoreException,
            FileNotFoundException,
            IOException,
            NoSuchAlgorithmException,
            CertificateException {

        char[] passphrase;
        InputStream in;
        OutputStream outS;
        Certificate cert;

        Provider bcProvider = loadProvider("org.bouncycastle.jce.provider.BouncyCastleProvider");
        KeyStore ksJKS;
        KeyStore ksBKS;

        ksBKS = KeyStore.getInstance("BKS", bcProvider);
        ksJKS = KeyStore.getInstance("JKS");

        passphrase = (((passwd == null) || (passwd.isEmpty())) ? "changeit" : passwd).toCharArray();

        File inFile = new File((!reverse) ? jks : bks);
        File outFile = new File((!reverse) ? bks : jks);

        in = new FileInputStream(inFile);
        if (!reverse) {
            ksJKS.load(in, passphrase);
        } else {
            ksBKS.load(in, passphrase);
        }
        in.close();

        if (!reverse) {
            ksBKS.load(null, passphrase);
        } else {
            ksJKS.load(null, passphrase);
        }

        Enumeration e;
        if (!reverse) {
            e = ksJKS.aliases();
        } else {
            e = ksBKS.aliases();
        }
        String s;
        while (e.hasMoreElements()) {
            s = e.nextElement().toString();

            if (!reverse) {
                cert = ksJKS.getCertificate(s);
                ksBKS.setCertificateEntry(s, cert);
                
                outS = new FileOutputStream(outFile.getAbsoluteFile());
                ksBKS.store(outS, passphrase);
            } else {
                cert = ksBKS.getCertificate(s);
                ksJKS.setCertificateEntry(s, cert);
                
                outS = new FileOutputStream(outFile.getAbsoluteFile());
                ksJKS.store(outS, passphrase);
            }
            outS.close();
        }
    }
}

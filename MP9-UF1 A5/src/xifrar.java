import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class xifrar {

    public static SecretKey keygenKeyGeneration(int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();

            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }
        }
        return sKey;
    }

    public static SecretKey passwordKeyGeneration(String text, int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                byte[] data = text.getBytes("UTF-8");
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash, keySize/8);
                sKey = new SecretKeySpec(key, "AES");
            } catch (Exception ex) {
                System.err.println("Error generant la clau:" + ex);
            }
        }
        return sKey;
    }

    public static byte[] encryptData(SecretKey sKey, byte[] data) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return encryptedData;
    }


    public static byte[] decryptData(SecretKey sKey, byte[] data) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            decryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return decryptedData;
    }

    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public static byte[] encryptData(byte[] data, PublicKey pub) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return encryptedData;
    }

    public static byte[] decryptData (byte[] data, PrivateKey pri) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, pri);
            decryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error Desxifrant: " + ex);
        }
        return decryptedData;
    }

    public static KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        File f = new File (ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream (f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }

    public static PublicKey getPublicKey(String fitxer) throws CertificateException, FileNotFoundException {

        FileInputStream f = new FileInputStream(fitxer);
        CertificateFactory cer = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) cer.generateCertificate(f);

        return certificate.getPublicKey();
    }


    public static PublicKey getPublicKey(KeyStore ks, String alias, String pwMyKey) throws CertificateException,NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, IOException {

        FileInputStream f = new FileInputStream("/home/dam2a/Escriptori/Programación/keystore123.ks");

        ks.load(f, pwMyKey.toCharArray());
        Key key = ks.getKey(alias, pwMyKey.toCharArray());

        if (key instanceof PrivateKey) {

            X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
            PublicKey pk = certificate.getPublicKey();
            return pk;

        }
        else return null;

    }




    public static byte[] signData(byte[] data, PrivateKey priv) {
        byte[] signature = null;

        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(priv);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception ex) {
            System.err.println("Error signant les dades: " + ex);
        }
        return signature;
    }


    public static boolean validateSignature(byte[] data, byte[] signature, PublicKey pub) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(pub);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }

    public static byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
        byte[][] encWrappedData = new byte[2][];
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sKey = kgen.generateKey(); //clau simetrica
            //Algoritme de xifrat simetric
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            byte[] encMsg = cipher.doFinal(data); // dades
            //Algoritme de xifrat asimetric
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, pub);
            byte[] encKey = cipher.wrap(sKey);



            encWrappedData[0] = encMsg; //dades xifrades
            encWrappedData[1] = encKey; // clau xifrada
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return encWrappedData;
    }
    public static byte[] decryptWrappedData(byte[][] data, PrivateKey secret) {
        byte[] msgDes = null;

        byte[] encMsg = data[0]; // dades xifrades

        try {

            // Algoritme de xifrat asimetric
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.UNWRAP_MODE, secret);
            SecretKey sKey;
            sKey = (SecretKey)cipher.unwrap(data[1], "AES", Cipher.SECRET_KEY);

            //Algoritme de xifrat simetric
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, sKey);

            msgDes = cipher.doFinal(encMsg);


        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException ex) {
            System.err.println("Ha succeït un error desxifrant: " + ex);
        }

        //dades
        return msgDes;
    }
}

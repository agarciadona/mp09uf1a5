import javax.crypto.SecretKey;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Scanner;

public class main {

    public static void main (String [] args) throws Exception {
        Scanner sc =  new Scanner(System.in);
        String msg = sc.nextLine();
        System.out.println("ex 1.1");

        KeyPair pardekeys = xifrar.randomGenerate(1024);
        PublicKey publicKey = pardekeys.getPublic();
        PrivateKey privateKey = pardekeys.getPrivate();

        byte[] encriptedData = xifrar.encryptData(msg.getBytes(),publicKey);
        System.out.println(new String(encriptedData));

        byte[] decriptedData = xifrar.decryptData(encriptedData,privateKey);
        System.out.println(new String(decriptedData));

        System.out.println("publica:\n" + pardekeys.getPublic());
        System.out.println("privada:\n" + pardekeys.getPrivate());

        System.out.println("ex 2");
        KeyStore ks = null;
        try {
            ks =  xifrar.loadKeyStore("/home/usuario/keystore_nickname.ks","usuari");
            System.out.println("Keystore Type: "+ ks.getType());
            System.out.println("Mida: "+ ks.size());
            System.out.println("Keys alias : "+ks.aliases().nextElement());
            System.out.println("Certificat: "+ks.getCertificate("mykey"));
            System.out.println(ks.getCertificate("mykey").getPublicKey().getAlgorithm());

        } catch (Exception e) {
            e.printStackTrace();
        }

        String passwd = "usuari";
        SecretKey sk = xifrar.passwordKeyGeneration(passwd,128);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(sk);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection("password".toCharArray());

        try {
            ks.setEntry("mykeyV2",secretKeyEntry,protectionParameter);
            FileOutputStream fos = new FileOutputStream("/home/usuario/keystore_nickname.ks");
            ks.store(fos, "usuari".toCharArray());
        } catch (KeyStoreException | FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("ex 3");

        String ruta = "/home/usuario/Escritorio/jordi.cer";
        PublicKey pk = xifrar.getPublicKey(ruta);
        System.out.println(pk);

        System.out.println("ex 4");

        String keyStoreFilePath = "/home/usuario/keystore_nickname.ks";
        String pass = "usuari";
        KeyStore keyStore = xifrar.loadKeyStore(keyStoreFilePath, pass);
        System.out.println(xifrar.loadKeyStore(keyStoreFilePath, pass));

        System.out.println("ex 5");
        System.out.println("pon cosas");
        String cosa = sc.nextLine();
        byte [] cosas = cosa.getBytes();
        byte [] signature = xifrar.signData(cosas, pardekeys.getPrivate());
        String signatura =  new String(signature);
        System.out.println(signatura);

        System.out.println("ex 6");


        boolean ValidSign = xifrar.validateSignature(cosas,signature, pardekeys.getPublic());
        System.out.println("Validesa: "+ValidSign);

        System.out.println("ex 2.2");
        byte [] data = "mucho texto".getBytes();

        KeyPair keypair = xifrar.randomGenerate(1024);
        PrivateKey privatekey = keypair.getPrivate();
        PublicKey publickey = keypair.getPublic();

        byte [][] encWrappedData = xifrar.encryptWrappedData(data, publickey);

        System.out.println("Msg encriptat: " + new String(encWrappedData[0]));
        System.out.println("key encriptada " + new String(encWrappedData[1]));
        byte [] decWrappedData = xifrar.decryptWrappedData(encWrappedData, privatekey);
        System.out.println(" Msg original desencriptat " + new String(decWrappedData));

    }
}

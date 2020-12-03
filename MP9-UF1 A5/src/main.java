import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class main {

    public static void main (String [] args){
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

        System.out.println("ex 1.2");
        String pathKeystore = "";

    }
}

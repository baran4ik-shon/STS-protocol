package task2.sts;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class KeyUtils {
    public static final int KEY_LENGTH = 1024;


    public static void generate(String filename){
        try {
            // Generate KeyPair
            KeyPairGenerator keyPG = KeyPairGenerator.getInstance("RSA");
            keyPG.initialize(KEY_LENGTH , new SecureRandom());
            KeyPair keyPair = keyPG.generateKeyPair();

            // Write Public Key
            X509EncodedKeySpec pk = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
            FileOutputStream pkFOS = new FileOutputStream(filename + ".pkey");
            pkFOS.write(pk.getEncoded());
            pkFOS.close();

            // Write Secret Key
            PKCS8EncodedKeySpec sk = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
            FileOutputStream skFOS = new FileOutputStream(filename + ".skey");
            skFOS.write(sk.getEncoded());
            skFOS.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static KeyPair load(String filename){
        try {
            // Read Public Key
            FileInputStream pkFIS = new FileInputStream(filename + ".pkey");
            byte[] pkBuffer = new byte[KEY_LENGTH];
            pkFIS.read(pkBuffer);
            pkFIS.close();

            // Read Secret Key
            FileInputStream skFIS = new FileInputStream(filename + ".skey");
            byte[] skBuffer = new byte[KEY_LENGTH];
            skFIS.read(skBuffer);
            skFIS.close();

            // Generate KeyPair
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                    pkBuffer);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                    skBuffer);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args){
        generate("server");
        generate("client");
    }
}

package task2.sts;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;


public class STSImplementation {
    private static final int PRIME_LENGTH = 1024; //bits
    private static final int IV_LENGTH = 8; //bits
    private static final int HMAC_LENGTH = 32; //bytes

    private SecretKey sharedKey;
    private SecureRandom random;
    private byte[] iv;

    public STSImplementation() {
        this.random = new SecureRandom();
        this.iv = new byte[IV_LENGTH];
    }

    public void startSTSAgreement(BufferedReader in, PrintWriter out) {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
            KeyFactory keyFactory = KeyFactory.getInstance("DH");

            BigInteger primeModules = this.generateBigPrime(PRIME_LENGTH);
            BigInteger generator = this.generateBigPrime(PRIME_LENGTH);
            this.random.nextBytes(this.iv);

            DHParameterSpec dhPS = new DHParameterSpec(primeModules, generator);
            keyPairGen.initialize(dhPS, this.random);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // send @generator, @primeModules, @publicKey and @iv to Client
            out.println(generator);
            out.println(primeModules);
            out.println(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            out.println(Base64.getEncoder().encodeToString(this.iv));
            out.flush();

            //receive @publicKey from Client
            byte[] pkBytes = Base64.getDecoder().decode(in.readLine());
            X509EncodedKeySpec ks = new X509EncodedKeySpec(pkBytes);
            PublicKey pkClient = keyFactory.generatePublic(ks);

            //compute @sharedKey
            keyAgree.init(keyPair.getPrivate());
            keyAgree.doPhase(pkClient, true);
            byte[] rawValue = keyAgree.generateSecret();
            this.sharedKey = new SecretKeySpec(rawValue, 0, 24, "TripleDES");

            // read keyPair Sign
            KeyPair keyPairRSA = KeyUtils.load("server");
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(keyPairRSA.getPrivate());
            keyFactory = KeyFactory.getInstance("RSA");

            //send publicKeySign to client
            out.println(Base64.getEncoder().encodeToString(
                    new X509EncodedKeySpec(keyPairRSA.getPublic().getEncoded()).getEncoded()));
            out.flush();

            //read client publicKeySign
            PublicKey pkSignClient = keyFactory.generatePublic(
                    new X509EncodedKeySpec(
                            Base64.getDecoder().decode(
                                    in.readLine())));

            // receive Client signature
            byte[] signClient = this.decrypt(Base64.getDecoder().decode(in.readLine()));

            sign.update(keyPair.getPublic().getEncoded());
            sign.update(pkClient.getEncoded());

            // send signature to Client
            out.println(Base64.getEncoder().encodeToString(this.encrypt(sign.sign())));
            out.flush();

            // verify the signature
            Signature clientSign = Signature.getInstance("SHA256withRSA");
            clientSign.initVerify(pkSignClient);
            clientSign.update(pkClient.getEncoded());
            clientSign.update(keyPair.getPublic().getEncoded());

            if (!clientSign.verify(signClient))
                throw new IllegalStateException("Invalid Signature!\n");
            else
                System.out.println("Validation successful");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void proceedSTSAgreement(BufferedReader in, PrintWriter out) {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
            KeyFactory keyFactory = KeyFactory.getInstance("DH");

            // receive @generator, @primeModules, @publicKey and @iv from Server
            BigInteger generator = new BigInteger(String.valueOf(in.readLine()));
            BigInteger primeModules = new BigInteger(String.valueOf(in.readLine()));
            byte[] publicKey = Base64.getDecoder().decode(in.readLine());
            this.iv = Base64.getDecoder().decode(in.readLine());
            DHParameterSpec dhPS = new DHParameterSpec(primeModules, generator);
            keyPairGen.initialize(dhPS, new SecureRandom());
            KeyPair keyPair = keyPairGen.generateKeyPair();


            X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKey);
            PublicKey pkServer = keyFactory.generatePublic(ks);

            // send @publicKey to Client
            out.println(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            out.flush();

            // compute @sharedKey
            keyAgree.init(keyPair.getPrivate());
            keyAgree.doPhase(pkServer, true);
            byte[] rawValue = keyAgree.generateSecret();
            this.sharedKey = new SecretKeySpec(rawValue, 0, 24, "TripleDES");

            //**************************//

            // read keyPair Sign
            KeyPair keyPairRSA = KeyUtils.load("client");
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(keyPairRSA.getPrivate());
            keyFactory = KeyFactory.getInstance("RSA");

            // send publicKeySign to Server
            out.println(Base64.getEncoder().encodeToString(
                    new X509EncodedKeySpec(keyPairRSA.getPublic().getEncoded()).getEncoded()));
            out.flush();

            // read Server publicKeySign
            PublicKey pkSignServer = keyFactory.generatePublic(
                    new X509EncodedKeySpec(
                            Base64.getDecoder().decode(
                                    in.readLine())));

            sign.update(keyPair.getPublic().getEncoded());
            sign.update(pkServer.getEncoded());

            // send signature to Server
            out.println(Base64.getEncoder().encodeToString(this.encrypt(sign.sign())));
            out.flush();

            // receive Server signature
            byte[] aux = Base64.getDecoder().decode(in.readLine());
            byte[] signServer = this.decrypt(aux);


            // verify the signature
            Signature serverSign = Signature.getInstance("SHA256withRSA");
            serverSign.initVerify(pkSignServer);
            serverSign.update(pkServer.getEncoded());
            serverSign.update(keyPair.getPublic().getEncoded());

            if (!serverSign.verify(signServer))
                throw new IllegalStateException("Invalid Signature!\n");
            else
                System.out.println("Validation successful");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] encrypt(byte[] message) {
        byte[] cryptogram = null;
        try {
            Cipher cipher = Cipher.getInstance("TripleDES/CTR/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.sharedKey, new IvParameterSpec(iv));

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(this.sharedKey);

            byte[] cipherText = cipher.doFinal(message);
            byte[] hMac = mac.doFinal(cipherText);

            cryptogram = new byte[cipherText.length + HMAC_LENGTH];
            System.arraycopy(hMac, 0, cryptogram, 0, HMAC_LENGTH);
            System.arraycopy(cipherText, 0, cryptogram, HMAC_LENGTH, cipherText.length);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cryptogram;
    }


    public byte[] decrypt(byte[] message) {
        byte[] plainText = null;
        try {
            byte[] hMac = Arrays.copyOfRange(message, 0, HMAC_LENGTH);
            byte[] cipherText = Arrays.copyOfRange(message, HMAC_LENGTH, message.length);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(this.sharedKey);
            byte[] hMac2 = mac.doFinal(cipherText);

            if (MessageDigest.isEqual(hMac, hMac2)) {
                Cipher cipher = Cipher.getInstance("TripleDES/CTR/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, this.sharedKey, new IvParameterSpec(iv));
                plainText = cipher.doFinal(cipherText);
            } else
                throw new IllegalAccessException("Problem: intrusion attempt!");

        } catch (Exception e) {
            e.printStackTrace();
        }
        return plainText;
    }

    private BigInteger generateBigPrime(int bits) {
        return BigInteger.probablePrime(bits, random);
    }
}

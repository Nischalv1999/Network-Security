

import java.io.*;
import java.lang.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class Alice implements Runnable {
    

  public static Integer PORT = 8879;

  PublicKey bobPublicKey;
  PrivateKey alicePrivateKey;


Random rand = new Random();

 static long R_Alice,R_Bob,masterSecret;

 SecretKey key1;
 SecretKey key2;
 SecretKey key3;
 SecretKey key4;

 static byte[] ivBytes = new byte[]{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
 static IvParameterSpec ivectorSpecv = new IvParameterSpec(ivBytes);
 


  
// a.start() in Multithreading class runs this function
  public void run() {
    getCertFromCA();
    recieveCertificateFromBob();
    R_Alice=rand.nextLong();
    System.out.println("Original R_alice: "+R_Alice);
    initialisePublicAndPrivateKeys();
    sendMsg1RecieveMsg2FromBob();
    performXOR();
    byte[] encryptedMasterSecret= encryptNonce(masterSecret, bobPublicKey);
    sendMasterSecretToBob(encryptedMasterSecret);
  }

  
    private void sendMasterSecretToBob(byte[] encryptedMasterSecret) 
  {
    List<Object> msg3ToBob=new ArrayList<>();
    try {
     Socket BobSocket = new Socket("localhost", 8889);

      byte[] hashedMasterSecret=computeHash(encryptedMasterSecret,"my_secret_key"+"CLIENT");
      msg3ToBob.add("Msg3");
      msg3ToBob.add(encryptedMasterSecret);
      msg3ToBob.add(hashedMasterSecret);
      System.out.println("Generated master secret at Alice: "+masterSecret);
      
      //generating 4 keys using master secret
      byte[] keyBytes;
      keyBytes = hash(masterSecret);
      // Split the key bytes into 4 parts and use each part to generate a key
    byte[] keyBytes1 = new byte[keyBytes.length / 4];
    byte[] keyBytes2 = new byte[keyBytes.length / 4];
    byte[] keyBytes3 = new byte[keyBytes.length / 4];
    byte[] keyBytes4 = new byte[keyBytes.length / 4];
    System.arraycopy(keyBytes, 0, keyBytes1, 0, keyBytes.length / 4);
    System.arraycopy(keyBytes, keyBytes.length / 4, keyBytes2, 0, keyBytes.length / 4);
    System.arraycopy(keyBytes, keyBytes.length / 2, keyBytes3, 0, keyBytes.length / 4);
    System.arraycopy(keyBytes, keyBytes.length * 3 / 4, keyBytes4, 0, keyBytes.length / 4);
    
     this.key1 = new SecretKeySpec(keyBytes1, "DES");
    this.key2 = new SecretKeySpec(keyBytes2, "DES");
    this.key3 = new SecretKeySpec(keyBytes3, "HmacSHA1");
     this.key4 = new SecretKeySpec(keyBytes4, "HmacSHA1");

     System.out.println("Alice: secret key1 generated : "+this.key1);
     System.out.println("Alice: secret key2 generated : "+this.key2);
     System.out.println("Alice: secret key3 generated : "+this.key3);
     System.out.println("Alice: secret key4 generated : "+this.key4);
      ObjectOutputStream objectOutputStream = new ObjectOutputStream(BobSocket.getOutputStream());
      objectOutputStream.writeObject(msg3ToBob);
      
      ObjectInputStream objectInputStream = new ObjectInputStream(BobSocket.getInputStream());
      List<Object> listOfMessages = (List<Object>) objectInputStream.readObject();
      byte[] encryptedFileBytes=(byte[]) listOfMessages.get(0);
      byte[] encryptedHashedFileBytes=(byte[]) listOfMessages.get(1);


      System.out.println("Alice says: Recieved encrypted file from Bob ");

      // Verifying file integrity
      if(verifyFileHash(encryptedFileBytes, encryptedHashedFileBytes, key4))
      {
        System.out.println("Alice says: File integrity verified!!");
      }
      else
      {
        System.out.println("Alice says: File integrity verification FAILED!!");
      }
      byte[]decryptedFileBytes= decryptWithKey(key2,encryptedFileBytes);
      FileOutputStream fileOut;
      fileOut = new FileOutputStream("ClientPrograms/NSAssignment-5.pdf");
    fileOut.write(decryptedFileBytes, 0, decryptedFileBytes.length);
    System.out.println("Alice says: File Transfered Successfully!!!");

    fileOut.close();
       

    } catch (InvalidKeyException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (UnknownHostException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (ClassNotFoundException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (IllegalBlockSizeException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (BadPaddingException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

  }


    private void performXOR() 
  {
    byte[] nonceBytes1 = ByteBuffer.allocate(Long.BYTES).putLong(R_Alice).array();
    byte[] nonceBytes2 = ByteBuffer.allocate(Long.BYTES).putLong(R_Bob).array();
    byte[] xorResult = new byte[Long.BYTES];
    for (int i = 0; i < Long.BYTES; i++) {
        xorResult[i] = (byte) (nonceBytes1[i] ^ nonceBytes2[i]);
    }
    masterSecret= ByteBuffer.wrap(xorResult).getLong();
  }


    private void initialisePublicAndPrivateKeys() {
     //Inititalising Alice's Private key and Bob's public key
      try {
        //Loading Alice's Private key from alice.jks file
        KeyStore aliceKeyStore;
        aliceKeyStore = KeyStore.getInstance("JKS");
        FileInputStream aliceKeyStoreFile = new FileInputStream("ClientPrograms/alice.jks");

        aliceKeyStore.load(aliceKeyStoreFile, "meka123".toCharArray());
        alicePrivateKey = (PrivateKey) aliceKeyStore.getKey("alice", "meka123".toCharArray());


 // Load Bob's's public key certificate from bob.crt file
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      FileInputStream bobCertFile = new FileInputStream("ClientPrograms/bob.crt");
      java.security.cert.Certificate bobCert =  cf.generateCertificate(bobCertFile);
      bobPublicKey = bobCert.getPublicKey();

  

      } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
      } catch (CertificateException e) {
        e.printStackTrace();
      } catch (IOException e) {
        e.printStackTrace();
      } catch (KeyStoreException e) {
        e.printStackTrace();
      } catch (UnrecoverableKeyException e) {
        e.printStackTrace();
      }
      
      
  }


    private void recieveCertificateFromBob()
  {
    try {
      //Sending Bob's Certificate to Alice
      Socket bobSocket = new Socket("localhost", 8889);
        List<Object> msg=new ArrayList<>();
        // Send a message requesting a certificate
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(bobSocket.getOutputStream());
        msg.add("I am Alice and I want Bob's certificate");
        objectOutputStream.writeObject(msg);
  
      // Receive the certificate from the CA
      InputStream in = bobSocket.getInputStream();
          byte[] fileBytes = new byte[1024];
          FileOutputStream fileOut = new FileOutputStream("ClientPrograms/bob.crt");
          int bytesRead = in.read(fileBytes, 0, fileBytes.length);
          fileOut.write(fileBytes, 0, bytesRead);
          fileOut.close();
          System.out.println("Alice says: Recieved Certificate from Bob");
          in.close();
          bobSocket.close();

          FileInputStream inputStream = new FileInputStream("ClientPrograms/bob.crt");
CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
X509Certificate cert = (X509Certificate) certFactory.generateCertificate(inputStream);

// Verify the certificate by checking if it is currently valid
cert.checkValidity();

// If the certificate is valid and trusted, the program will reach this point
System.out.println("Alice says: Bob's Certificate is valid and trusted.");

  } catch (IOException e) {
    // TODO Auto-generated catch block
    e.printStackTrace();
  } catch (CertificateException e) {
    // TODO Auto-generated catch block
    e.printStackTrace();
  } 

  }


    private void sendMsg1RecieveMsg2FromBob() 
  {
    Socket BobSocket;
    try {

      BobSocket = new Socket("localhost", 8889);

      List<Object> msg=new ArrayList<>();
      // Send a message requesting a certificate
      ObjectOutputStream objectOutputStream = new ObjectOutputStream(BobSocket.getOutputStream());
      System.out.println("Sending msg1 to bob");

      byte[] encrypted_RAlice=encryptNonce(R_Alice, bobPublicKey);
      msg.add("RSA");
      msg.add(encrypted_RAlice);
      
// read the file into a byte array
File fileToSend = new File("ClientPrograms/alice.crt");
byte[] fileBytes = Files.readAllBytes(fileToSend.toPath());
// send the file to the client
msg.add(fileBytes);

byte[] msg1="RSA".getBytes();
        // Compute keyed SHA-1 hash for msg1 message
        byte[] msg1Hashed = computeHash(msg1, "my_secret_key" + "CLIENT");

        // Compute keyed SHA-1 hash for msg2 message
        
        byte[] msg2Hashed = computeHash(encrypted_RAlice, "my_secret_key" + "CLIENT");

        msg.add(msg1Hashed);
        msg.add(msg2Hashed);
objectOutputStream.writeObject(msg);


ObjectInputStream objectInputStream = new ObjectInputStream(BobSocket.getInputStream());
      List<Object> listOfMessages = (List<Object>) objectInputStream.readObject();

      //Verifying hashed msgs
      String s1= (String)listOfMessages.get(0);
      byte[] m1=s1.getBytes();
      byte[] m1Hashed=(byte[]) listOfMessages.get(2);

      byte[] m2=(byte[]) listOfMessages.get(1);
      byte[] m2Hashed=(byte[]) listOfMessages.get(3);
      if (verifyHash(m1, m1Hashed,  "my_secret_key"+ "SERVER")) {
        System.out.println("Alice: Server msg1 hash verified at client.");
    } else {
        System.out.println("Alice: Server msg1 hash verification failed at client.");
    }
    if (verifyHash(m2, m2Hashed,  "my_secret_key"+ "SERVER")) {
      System.out.println("Alice: Server msg2 hash verified at client.");
  } else {
      System.out.println("Alice: Server  msg2 hash verification failed at client.");
  }
      long decryptedRBob=decryptNonce(m2, alicePrivateKey);
      R_Bob=decryptedRBob;
System.out.println("Decrypted R-Bob: "+decryptedRBob);

//close the socket and server
objectInputStream.close();
BobSocket.close();
objectOutputStream.close();

} catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (InvalidKeyException e) {
  // TODO Auto-generated catch block
  e.printStackTrace();
} catch (NoSuchAlgorithmException e) {
  // TODO Auto-generated catch block
  e.printStackTrace();}
catch (ClassNotFoundException e) {
  // TODO Auto-generated catch block
  e.printStackTrace();
}
       
  }


    private byte[] encryptNonce(long nonce, PublicKey publicKey) {

  // Encrypt a nonce using a public key
      Cipher cipher;
      try {
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] result=new byte[Long.BYTES];
                for (int i = 0; i < Long.BYTES; i++) 
                {
                    result[i] = (byte) (nonce >> (i * 8));
                }
        byte[] cipherText = cipher.doFinal(result);
        //System.out.println("Encrypted message: " + new String(cipherText));
            return cipherText;
      } catch (NoSuchAlgorithmException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      } catch (NoSuchPaddingException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      } catch (InvalidKeyException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      } catch (IllegalBlockSizeException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      } catch (BadPaddingException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      }
     
      return null;
    }

    private long decryptNonce(byte[] nonce, PrivateKey privateKey) {

      // Decrypt a message using a private key
          Cipher cipher;
          try {
            cipher = Cipher.getInstance("RSA");

             // Decrypt the message using Alice's private key
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      byte[] decryptedText = cipher.doFinal(nonce);
      System.out.println("Decrypted message: " + new String(decryptedText));

            long result = 0; //result is the nonce after decrypting
      for (int i = 0; i < decryptedText.length; i++) {
        result |= ((long) decryptedText[i] & 0xFF) << (8 * i);
      }

      return result;
          } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
          } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
          } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
          } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
          } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
          }
         
          return 0;
        }
    
      

    private void getCertFromCA() 
  {
    try {
        Socket CASocket = new Socket("localhost", 8899);
        List<Object> msg=new ArrayList<>();
        // Send a message requesting a certificate
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(CASocket.getOutputStream());
        msg.add("I am Alice and I want a certificate");
        objectOutputStream.writeObject(msg);
  
        // Receive the certificate from the CA
        InputStream in = CASocket.getInputStream();
            byte[] fileBytes = new byte[1024];
            FileOutputStream fileOut = new FileOutputStream("ClientPrograms/alice.crt");
            int bytesRead = in.read(fileBytes, 0, fileBytes.length);
            fileOut.write(fileBytes, 0, bytesRead);
            fileOut.close();
            in.close();
            CASocket.close();
  
            System.out.println("Alice says: Received the certificate from the CA");
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } 
  }


  //getting the port number
  public Integer getPort() {
    return PORT;
}

private static byte[] computeHash(byte[] message, String key) throws NoSuchAlgorithmException, InvalidKeyException {
  //Computing hash of a message
  SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA1");
  Mac mac = Mac.getInstance("HmacSHA1");
  mac.init(signingKey);
  byte[] rawHash = mac.doFinal(message);
  return rawHash;
}

private static boolean verifyHash(byte[] message, byte[] hash, String key) throws NoSuchAlgorithmException, InvalidKeyException {
  byte[] expectedHash = computeHash(message, key);
  return Arrays.equals(expectedHash,hash);
}

public static byte[] hash(long value) throws NoSuchAlgorithmException {
  //Generating keys with the master secret using a SHA-256 hash function
  MessageDigest digest = MessageDigest.getInstance("SHA-256");
  byte[] hash = digest.digest(String.valueOf(value).getBytes());
  return hash;
}

public static byte[] decryptWithKey(SecretKey key, byte[] encryptedBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
//Decrypting the bytes[] recieved from another program
  Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
  cipher.init(Cipher.DECRYPT_MODE, key);
  byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
  return decryptedBytes;
}

private static byte[] computeFileHash(byte[] message, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
  Mac mac = Mac.getInstance("HmacSHA1");
  mac.init(key);
  byte[] rawHash = mac.doFinal(message);
  return rawHash;
}
private static boolean verifyFileHash(byte[] message, byte[] hash, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
  byte[] expectedHash = computeFileHash(message, key);
  return Arrays.equals(expectedHash,hash);
}


}




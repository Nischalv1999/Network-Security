

import java.io.*;
import java.lang.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

// When Bob thread runs it runs the below run() method
public class Bob implements Runnable {
    public static Integer PORT = 8889;
  public boolean port2 = false;
 

   
  static long R_Bob,R_Alice,masterSecret;
  Random rand = new Random();
  static PublicKey alicePublicKey;
  static PrivateKey bobPrivateKey;

  SecretKey key1;
  SecretKey key2;
  SecretKey key3;
  SecretKey key4;
  static byte[] ivBytes = new byte[]{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
  static IvParameterSpec ivectorSpecv = new IvParameterSpec(ivBytes);
  

//getting the port number of Bob
  public Integer getPort() {
   
    return PORT;
  }

  @Override
  public void run() {

    ServerSocket serverSocket;
    Socket clientSocket;
    while(true)
    {
    try {
      
      serverSocket = new ServerSocket(8889);
  
  
      // System.out.println("Waiting for Alice connection...");
           clientSocket = serverSocket.accept();
          System.out.println("Client connected: " + clientSocket);
          ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream());
  
              List<Object> listOfMessages = (List<Object>) objectInputStream.readObject();
  
              if(listOfMessages.get(0).equals("RSA"))
              {//CHoosing the supported cipher as RSA and sending the msg2 response back 
                getMsg2(listOfMessages, clientSocket);
                R_Bob=rand.nextLong();
                List<Object> msg2ToAlice=new ArrayList<>();
                msg2ToAlice.add("RSA");
                byte[] encryptedRBob=encryptNonce(R_Bob,alicePublicKey);
                msg2ToAlice.add(encryptedRBob);
                msg2ToAlice.add(computeHash("RSA".getBytes(),"my_secret_key"+"SERVER" ));
                msg2ToAlice.add(computeHash(encryptedRBob, "my_secret_key"+"SERVER"));
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            objectOutputStream.writeObject(msg2ToAlice);
      
                
              }
              else if(listOfMessages.get(0).equals("I am Alice and I want Bob's certificate"))
              {//sending Bob's cert to Alice
                sendCertToAlice(listOfMessages, clientSocket);
              }
              else if(listOfMessages.get(0).equals("Msg3"))
              {
                checkMsg3AndSendFileToClient(listOfMessages, clientSocket);
                System.out.println("Bob: secret key1: "+this.key1);
                System.out.println("Bob: secret key2: "+this.key2);
                System.out.println("Bob: secret key3: "+this.key3);
                System.out.println("Bob: secret key4: "+this.key4);  
              }
               serverSocket.close();
               clientSocket.close();
  
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (ClassNotFoundException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    
    }
    
    
  }

  private void checkMsg3AndSendFileToClient(List<Object> listOfMessages, Socket clientSocket) 
  {
    
    //verifying hashed messages
    byte[] m1=(byte[]) listOfMessages.get(1);
    byte[] m1Hashed=(byte[]) listOfMessages.get(2);
    try {
      if(verifyHash(m1, m1Hashed, "my_secret_key"+"CLIENT"))
      {
        System.out.println("Bob: Verified master secret hashed messages");
      }
      else
      {
        System.out.println("Bob: Verification of master secret hashed messages failed!!!");
      }
      long decrypted_masterSecret=decryptNonce(m1, bobPrivateKey);
      System.out.println("Decrypted master secret at Bob: "+ decrypted_masterSecret);
      masterSecret=decrypted_masterSecret;
      derive4keysfromMasterSecret(masterSecret);

      // Compare the original and decrypted file
File originalFile = new File("ServerPrograms/NetworkSecurityAssignment-5.pdf");
byte[] fileBytes = Files.readAllBytes(originalFile.toPath());
// Encrypt the file using key1
byte[] encryptedBytes = encryptWithKey(key2, fileBytes);

//computing hash of encrypted file
byte[] encryptedBytesHashed=computeFileHash(encryptedBytes,key4);

System.out.println("Bob says: Sending encrypted file to Alice ");
List<Object> msg4ToAlice=new ArrayList<Object>();
msg4ToAlice.add(encryptedBytes);
msg4ToAlice.add(encryptedBytesHashed);
ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            objectOutputStream.writeObject(msg4ToAlice);

    

    } catch (InvalidKeyException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    
  }

  private void derive4keysfromMasterSecret(long secret) 
  {
    // Derive 4 keys using a hash function
    byte[] keyBytes;
    try {
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
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
 
  }

  private void sendCertToAlice(List<Object> listOfMessages, Socket aliceSocket) {
//Sending Bob's Certificate to Alice
try {
  
  File fileToSend = new File("ServerPrograms/bob.crt");
byte[] bobFileBytes = Files.readAllBytes(fileToSend.toPath());
// send the file to the client
OutputStream out = aliceSocket.getOutputStream();
out.write(bobFileBytes);
out.flush();
} catch (UnknownHostException e) {
  // TODO Auto-generated catch block
  e.printStackTrace();
} catch (IOException e) {
  // TODO Auto-generated catch block
  e.printStackTrace();
}

// read the file into a byte array



  }

  private void getMsg2(List<Object> listOfMessages, Socket clientSocket) {
    // for(Object obj:listOfMessages){
    //   System.out.println("msgs in bob: "+obj);
    // }
    // Verifying Hashed Messages
    String s= (String) listOfMessages.get(0);
    byte[] msg1=s.getBytes();
    byte[] msg1Hashed=(byte[]) listOfMessages.get(3);

    byte[] msg2=(byte[]) listOfMessages.get(1);
    byte[] msg2Hashed=(byte[]) listOfMessages.get(4);


    try {
      if (verifyHash(msg1, msg1Hashed,  "my_secret_key"+ "CLIENT")) {
              System.out.println("Server msg1 hash verified at client.");
          } else {
              System.out.println("Server hash verification failed at client.");
          }
          if (verifyHash(msg2, msg2Hashed,  "my_secret_key"+ "CLIENT")) {
            System.out.println("Server msg2 hash verified at client.");
        } else {
            System.out.println("Server hash verification failed at client.");
        }
        
    } catch (InvalidKeyException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }


    byte[] fileBytes = new byte[1024];
            FileOutputStream fileOut;
            try {
              fileOut = new FileOutputStream("ServerPrograms/alice.crt");
              fileBytes=(byte[]) listOfMessages.get(2);
            fileOut.write(fileBytes, 0, fileBytes.length);
            fileOut.close();

            FileInputStream inputStream = new FileInputStream("Common/alice.crt");
CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
X509Certificate cert = (X509Certificate) certFactory.generateCertificate(inputStream);

// Verify the certificate by checking if it is currently valid
cert.checkValidity();

// If the certificate is valid and trusted, the program will reach this point
System.out.println("Bob says: Alice Certificate is valid and trusted.");


//Initialising Public key of Alice and Private Key of Bob
initialisePublicAndPrivateKeys();
byte[] encrypted_RAlice=(byte[]) listOfMessages.get(1);
long decrypted_RAlice=decryptNonce(encrypted_RAlice, bobPrivateKey);
System.out.println("Decrypted R alice at Bob: "+decrypted_RAlice);
R_Alice=decrypted_RAlice;
            } catch (FileNotFoundException e) {
              // TODO Auto-generated catch block
              e.printStackTrace();
            }
            //int bytesRead = in.read(fileBytes, 0, fileBytes.len`1gth);
 catch (IOException e) {
              // TODO Auto-generated catch block
              e.printStackTrace();
            } catch (CertificateException e) {
  // TODO Auto-generated catch block
  e.printStackTrace();
}
            
  }
  private void initialisePublicAndPrivateKeys() {
     
    try {
      KeyStore bobKeyStore;
      bobKeyStore = KeyStore.getInstance("JKS");
      FileInputStream bobKeyStoreFile = new FileInputStream("ServerPrograms/bob.jks");

      bobKeyStore.load(bobKeyStoreFile, "meka123".toCharArray());
      bobPrivateKey = (PrivateKey) bobKeyStore.getKey("bob", "meka123".toCharArray());


// Load Alice's public key certificate from alice.crt file
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    FileInputStream aliceCertFile = new FileInputStream("ServerPrograms/alice.crt");
    java.security.cert.Certificate aliceCert =  cf.generateCertificate(aliceCertFile);
    alicePublicKey = aliceCert.getPublicKey();

    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (CertificateException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (KeyStoreException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (UnrecoverableKeyException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    
    // Get Alice's private key from the keystore
    
}

private byte[] encryptNonce(long nonce, PublicKey publicKey) {

  // Encrypt a message using Bob's public key
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

      // Encrypt a message using Bob's public key
          Cipher cipher;
          try {
            cipher = Cipher.getInstance("RSA");

             // Decrypt the message using Alice's private key
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      byte[] decryptedText = cipher.doFinal(nonce);
      System.out.println("Decrypted message: " + new String(decryptedText));

            long result = 0; //result is the N2 after decrypting
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
    
        private static byte[] computeHash(byte[] message, String key) throws NoSuchAlgorithmException, InvalidKeyException {
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
          MessageDigest digest = MessageDigest.getInstance("SHA-256");
          byte[] hash = digest.digest(String.valueOf(value).getBytes());
          return hash;
      }

      public static byte[] encryptWithKey(SecretKey key, byte[] data) throws Exception {
        
        // Create a cipher instance and initialize it for encryption
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
    
        // Encrypt the data
        byte[] encryptedData = cipher.doFinal(data);
    
        
        return encryptedData;
    }
    public static byte[] decryptWithKey(SecretKey key, byte[] encryptedBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
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
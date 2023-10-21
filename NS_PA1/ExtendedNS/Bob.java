package ExtendedNS;

import java.io.*;
import java.lang.*;
import java.util.*;

import java.util.concurrent.CountDownLatch;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.net.*;
import java.security.*;

// This class extends Server and when Bob thread runs it runs the run() in Server Class

public class Bob extends Server{
    public static Integer PORT = 8889;
  public boolean port2 = false;
 

  static KeyGenerator keygenerator;
  static Cipher encryptCipherKB;
  static SecretKey KBob_KDC; 
  static SecretKey Kab;
  static long N3;
  static long Nb;
  static long N3Minus1;
  Random rand = new Random();
  Cipher cipherKab;
  byte[] encryptMsg4;
  List<Object> msg4List;

   CountDownLatch latch;

  public Bob(CountDownLatch latch) {
   this.latch = latch;
 }
 
 @Override
 CountDownLatch getLatch() {
   return this.latch;
 }
//creating the key K-bob and initialising cipher  
static{  
  try {
    keygenerator=KeyGenerator.getInstance("TripleDES");
    KBob_KDC= keygenerator.generateKey();
    encryptCipherKB=Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
    encryptCipherKB.init(Cipher.ENCRYPT_MODE, KBob_KDC,Alice.ivectorSpecv);

  } catch (NoSuchAlgorithmException e) {
    e.printStackTrace();
  } catch (NoSuchPaddingException e) {
    e.printStackTrace();
  } catch (InvalidKeyException e) {
    e.printStackTrace();
  } catch (InvalidAlgorithmParameterException e) {
    e.printStackTrace();
  }

}

  public Integer getPort() {
   
    return PORT;
  }
  
  //Returns the msg to the Server that Bob wants to send to the client.
  @Override
  List<Object> getServerMsg(List<Object> listOfMessages) {

      //Getting the the msg-2 to be sent to Alice
    if((listOfMessages.get(0)).equals("Alice wants to talk to Bob") )
    {    List<Object> msgToTrudy=getResponse0();
       return msgToTrudy;
  }
  // Here Bob just auntheticates Alice
  else if((listOfMessages.get(0)).equals("LastMessage"))
  {
    List<Object> msgToTrudy=getResponse3(listOfMessages);
       return msgToTrudy;
  }
  //Getting the msg-6 that should be sent to Alice
    else
  { List<Object> msgToTrudy=getResponse1(listOfMessages);
    return msgToTrudy;
  }
  }

    private List<Object> getResponse0()
     {
Nb=rand.nextLong();

byte[] kabEncrytNb=encryptNonce(Nb,KBob_KDC);
  
  Byte[] kabEncrytNb1Object= convertByteToObject(kabEncrytNb);
  
  List<Object> msgToTrudy=new ArrayList<>();
  System.out.println("--------------------------------------------------------------------------------------------------------");
  System.out.println("Bob says: Sending Nb encrypted with K-Bob to Alice");
  System.out.println("Message 2: Bob ---> Alice is as follows: ");
  System.out.println("Encrypted Nb: "+Arrays.toString(kabEncrytNb1Object));
  System.out.println("--------------------------------------------------------------------------------------------------------");

  msgToTrudy.add(kabEncrytNb1Object);
  return msgToTrudy;

    }

  private List<Object> getResponse3(List<Object> listOfMessages)
  {

    Byte[] bytes=(Byte[]) listOfMessages.get(1);
    byte[] byteArray = new byte[bytes.length];

for (int i = 0; i < bytes.length; i++) {
byteArray[i] = bytes[i];
}


try {
  //Decrypting the msg-7 recieved from Alice
  Cipher c=Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
  
  c.init(Cipher.DECRYPT_MODE, Kab, Alice.ivectorSpecv);
  
  long N3Minus1Decrypted = decryptNonce(byteArray,Kab);
  //System.out.println("N3 calculated from N3-1 that was recieved from Alice: ");
  System.out.println(N3Minus1Decrypted+1);
  System.out.println("Actual N3 created by Bob: "+N3);
 
  // Checking the N3 value recieved from Alice and checking it with actual N3
  if(N3Minus1Decrypted+1==N3)
  {
    System.out.println("Bob says: Alice Successfully Authenticated!!!");
  }
  byte[] kabEncrytN3Minus1=Alice.encryptNonce(N3Minus1Decrypted);
  
  Byte[] kabEncrytN3Minus1Object= convertByteToObject(kabEncrytN3Minus1);
  
  List<Object> msgToTrudy=new ArrayList<>();
  
  msgToTrudy.add(kabEncrytN3Minus1Object);
  return msgToTrudy;
  
  
  
  } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
  e.printStackTrace();
  } catch (InvalidKeyException e) {
  e.printStackTrace();
   
  } catch (InvalidAlgorithmParameterException e) {
    // TODO Auto-generated catch block
    e.printStackTrace();
  }

    return null;
  }

  private List<Object> getResponse1(List<Object> listOfMessages)
   {
    System.out.println("Bob says: Recieved ticket from Alice");
    Byte bytes1[]=(Byte[])listOfMessages.get(0);

      byte[] encryptedN2 = new byte[bytes1.length];
  
  for (int i = 0; i < bytes1.length; i++) 
  {
    encryptedN2[i] = bytes1[i];
  }
  System.out.println("EncryptedN2 in bob: "+Arrays.toString(encryptedN2));
  Byte bytes2[]=(Byte[])listOfMessages.get(1);
  
      byte[] ticket = new byte[bytes2.length];
  
  for (int i = 0; i < bytes2.length; i++) 
  {
    ticket[i] = bytes2[i];
  }
  Kab=(SecretKey) listOfMessages.get(2);
  System.out.println("Bob says: Kab extracted from the ticket: "+Kab);
  long N2=decryptNonce(encryptedN2,Kab);
  System.out.println("Bob says: N2 after decryption using K-ab: "+N2);
  N3=rand.nextLong();
  // byte[] msg4 = KDC.concatenate(N2-1,N3);
  byte[] encN2Minus1=Alice.encryptNonce(N2-1);
  byte[] encN3=Alice.encryptNonce(N3);

Byte[] m1=convertByteToObject(encN2Minus1);
Byte[] m2=convertByteToObject(encN3);

System.out.println("--------------------------------------------------------------------------------------------------------");
System.out.println("Message 6: Bob ---> Alice is as follows:");
System.out.println("K-ab(N2-1,N3)");
System.out.println("--------------------------------------------------------------------------------------------------------");

System.out.println("N3 value created by Bob: "+N3);


//System.out.println("Actual encrypted N3 in Bob: "+Arrays.toString(m2));



  msg4List=new ArrayList<>();
  msg4List.add(m1);
  msg4List.add(m2);

  
  return msg4List;
 
  }

  

 // Convdrting Byte[] object to byte[]
  public static Byte[] convertByteToObject(byte[] kabEncrytN3) 
  {
    Byte[] byteObjectArray = new Byte[kabEncrytN3.length];

    for (int i = 0; i < kabEncrytN3.length; i++) {
        byteObjectArray[i] = Byte.valueOf(kabEncrytN3[i]);
    }
    return byteObjectArray;
  }

  
// Decrypting Nonce
  public static long decryptNonce(byte[] encryptedN2, SecretKey key) {
    Cipher desCipher;
    try {
      desCipher = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");

      desCipher.init(Cipher.DECRYPT_MODE, key, Alice.ivectorSpecv);


      byte[] decryptedN2=desCipher.doFinal(encryptedN2);

      long result = 0; //result is the N2 after decrypting
      for (int i = 0; i < decryptedN2.length; i++) {
        result |= ((long) decryptedN2[i] & 0xFF) << (8 * i);
      }

      return result;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
    } catch (BadPaddingException e) {
      e.printStackTrace();
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
    }
    return 0;
  }

  //Encrypting Nonce
  public static byte[] encryptNonce(long N, SecretKey key) 
  {
    Cipher CipherKANonce;
   try {
    CipherKANonce = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
    CipherKANonce.init(Cipher.ENCRYPT_MODE, key,Alice.ivectorSpecv);
    byte[] result=new byte[Long.BYTES];
              for (int i = 0; i < Long.BYTES; i++) 
              {
                  result[i] = (byte) (N >> (i * 8));
              }

    byte[] encryptedNonce = CipherKANonce.doFinal(result);

    return encryptedNonce;
  } 

  catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
    e.printStackTrace();
  } catch (InvalidKeyException e) {
    e.printStackTrace();
  } catch (IllegalBlockSizeException e) {
    e.printStackTrace();
  } catch (BadPaddingException e) {
    e.printStackTrace();
  } catch (InvalidAlgorithmParameterException e) {
    e.printStackTrace();
  }
  return null;

  }



}
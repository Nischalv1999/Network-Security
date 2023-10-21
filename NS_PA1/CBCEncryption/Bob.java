package CBCEncryption;

import java.io.*;
import java.lang.*;
import java.util.*;

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
  static long N3Minus1;
  Random rand = new Random();
  Cipher cipherKab;
  byte[] encryptMsg4;
  List<Object> msg4List;

  static byte[] ivBytes = new byte[]{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
  static IvParameterSpec ivectorSpecv = new IvParameterSpec(ivBytes);

  //creating the key K-bob and initialising cipher  
static{  
  try {
    keygenerator=KeyGenerator.getInstance("TripleDES");
    KBob_KDC= keygenerator.generateKey();
    encryptCipherKB=Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
encryptCipherKB.init(Cipher.ENCRYPT_MODE, KBob_KDC,ivectorSpecv);

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
//getting the port number of Bob
  public Integer getPort() {
   
    return PORT;
  }

    //Returns the msg to the Server that Bob wants to send to the client.

  @Override
  List<Object> getServerMsg(List<Object> listOfMessages) {
  
    //Getting the the final msg response(K-ab(N3-1)) from Bob to Trudy
    if((listOfMessages.get(0)).equals("Trudy") )
    {    List<Object> msgToTrudy=getResponse2(listOfMessages);
       return msgToTrudy;
  }
    //Validating the Encrypted N3-1 recieved from Trudy.
  else if((listOfMessages.get(0)).equals("TrudyLast"))
  {
    List<Object> msgToTrudy=getResponse3(listOfMessages);
       return msgToTrudy;
  }
    else
  {     // Getting the response Msg-4 from Bob to Trudy
    List<Object> msgToTrudy=getResponse1(listOfMessages);
    return msgToTrudy;
  }
  }

  private List<Object> getResponse3(List<Object> listOfMessages)
  {

    Byte[] bytes=(Byte[]) listOfMessages.get(1);
    byte[] byteArray = new byte[bytes.length];

for (int i = 0; i < bytes.length; i++) {
byteArray[i] = bytes[i];
}

System.out.println("Bob says: encrypted N3-1 recieved from Trudy: "+Arrays.toString(byteArray));

try {
  Cipher c=Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
  
  c.init(Cipher.DECRYPT_MODE, Kab, ivectorSpecv);

  // Decrypting the N3-1 
  long N3Minus1Decrypted = decryptNonce(byteArray);

  System.out.println("Actual N3 created by Bob: "+N3);
  System.out.println("N3 recieved from Trudy to Bob: "+N3Minus1Decrypted+1);
 
    //Comparing the N3-1 recieved from Trudy to N3-1 stored at Bob

  if(N3Minus1Decrypted==N3Minus1)
  {
    System.out.println("Trudy Successfully impersonated Alice!!!");
  }
  else
  {
    System.out.println("Trudy was not able to impersonate Bob");
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
    e.printStackTrace();
  }

    return null;
  }

  private List<Object> getResponse1(List<Object> listOfMessages)
   {
    Byte bytes1[]=(Byte[])listOfMessages.get(0);

      byte[] encryptedN2 = new byte[bytes1.length];
  
  for (int i = 0; i < bytes1.length; i++) 
  {
    encryptedN2[i] = bytes1[i];
  }
  
  Byte bytes2[]=(Byte[])listOfMessages.get(1);
  
      byte[] ticket = new byte[bytes2.length];
  
  for (int i = 0; i < bytes2.length; i++) 
  {
    ticket[i] = bytes2[i];
  }
  
  Kab=(SecretKey) listOfMessages.get(2);
  long N2=decryptNonce(encryptedN2);
  System.out.println("N2 in Bob: "+N2);
  N3=rand.nextLong();
  System.out.println("N3 in Bob: "+N3);
  System.out.println("--------------------------------------------------------------------------------------------------------");
  System.out.println("Message 3: Alice ---> Bob");
  System.out.println("Ticket to Bob");
  System.out.println("K-ab Encrypted N2");
  System.out.println("--------------------------------------------------------------------------------------------------------");
  System.out.println("Bob decrypting the ticket with K-bob and extracting the secret key K-ab.......");
  System.out.println("Bob after decrypting the value of N2 with k-ab: "+N2);
  byte[] N2concatN3Minus1=KDC.concatenate(N2-1,N3);
  byte[] ecnryptedMsg= encryptBytes(N2concatN3Minus1);
  System.out.println("Actual encypted N2-1 and N3: "+Arrays.toString(ecnryptedMsg));
  byte[] encN2=Alice.encryptNonce(N2-1);
  byte[] encN3Minus1=Alice.encryptNonce(N3);

  System.out.println("Bob sending encrypted N3 value is as follows: "+ Arrays.toString(encN3Minus1));

  Byte[] m2=convertByteToObject(encN3Minus1);

  System.out.println("Actual encrypted N3 in Bob: "+Arrays.toString(m2));




Byte[] m1=convertByteToObject(ecnryptedMsg);

System.out.println("Actual encrypted N2-1 and N3 in Bob: "+Arrays.toString(m1));



  msg4List=new ArrayList<>();
  msg4List.add(m1);
  // msg4List.add(m2);

  
  return msg4List;
     
  }

   byte[] encryptBytes(byte[] n2concatN3Minus1)
   {
    Cipher c;
    try {
      c = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
      c.init(Cipher.ENCRYPT_MODE, Kab, ivectorSpecv);
      byte[] textEncrypted = c.doFinal(n2concatN3Minus1);
      return textEncrypted;
    } 
    catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
    } catch (BadPaddingException e) {
      e.printStackTrace();
    }
   
return null; 
  }

 

  private List<Object> getResponse2(List<Object> listOfMessages) {
   

    Byte[] bytes=(Byte[]) listOfMessages.get(1);
    byte[] byteArray = new byte[bytes.length];

for (int i = 0; i < bytes.length; i++) {
byteArray[i] = bytes[i];
}
System.out.println("Encrypted N3 recieved from Trudy: "+Arrays.toString(byteArray));

try {
Cipher c=Cipher.getInstance("TripleDES/CBC/PKCS5Padding");

c.init(Cipher.DECRYPT_MODE, Kab,ivectorSpecv);

//Decrypting N3 recieved from Trudy and sending N3-1 encrypted to Trudy.
long N3Decrypted = decryptNonce(byteArray);
//System.out.println("n3 decr: "+N3Decrypted);
long newN3=N3Decrypted-1;
N3Minus1=N3-1;

byte[] kabEncrytN3=Alice.encryptNonce(newN3);

Byte[] kabEncrytN3Object= convertByteToObject(kabEncrytN3);

List<Object> msgToTrudy=new ArrayList<>();

msgToTrudy.add(kabEncrytN3Object);
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

  public Byte[] convertByteToObject(byte[] kabEncrytN3) 
  {
    Byte[] byteObjectArray = new Byte[kabEncrytN3.length];

    for (int i = 0; i < kabEncrytN3.length; i++) {
        byteObjectArray[i] = Byte.valueOf(kabEncrytN3[i]);
    }
    return byteObjectArray;
  }

  

  private long decryptNonce(byte[] encryptedN2) {
    Cipher desCipher;
    try {
      desCipher = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");

      desCipher.init(Cipher.DECRYPT_MODE, Kab,ivectorSpecv);


      byte[] decryptedN2=desCipher.doFinal(encryptedN2);

      long result = 0; //result is the N2 after decrypting
      for (int i = 0; i < decryptedN2.length; i++) {
        result |= ((long) decryptedN2[i] & 0xFF) << (8 * i);
      }

      return result;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
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
    } catch (InvalidAlgorithmParameterException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    return 0;
  }
}
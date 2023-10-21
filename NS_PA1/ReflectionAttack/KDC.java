package ReflectionAttack;
import java.util.List;
import java.io.*;
import java.lang.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

import javax.crypto.*;

import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;


// This class extends Server and when KDC thread runs it runs the run() in Server Class

public class KDC extends Server{

  public static Integer PORT = 8899;
  private boolean expanded = false;


    //Getting port number of KDC
    public Integer getPort() {
        return PORT;
      }



  //Returns the msg to the Server that KDC wants to send to the client.
  @Override
    List<Object> getServerMsg(List<Object> listOfMessages) 
    {

try{
      Cipher desCipher=Alice.encryptCipherKA;

      long N1=(long)listOfMessages.get(0);
      String bob="Bob";
      System.out.println("--------------------------------------------------------------------------------------------------------");
      System.out.println("Message 1: Alice ---> KDC is as follows: ");

      System.out.println("N1: "+N1);
      System.out.println((String)listOfMessages.get(1));
      System.out.println("--------------------------------------------------------------------------------------------------------");

      System.out.println("KDC generating secret key Kab and ticket to Bob.........");
      

      

      SecretKey Kab=generateSecretKeyAliceBob();
byte[] ticket=generateTicketForBob(Kab);


      ArrayList<Byte> byteList=new ArrayList<Byte>();

 String encodedKab=(String)Base64.getEncoder().encodeToString(Kab.getEncoded());


// concatenating all the messages and encrypting.
  byte[] message = concatenate(N1, bob.getBytes(StandardCharsets.UTF_8), encodedKab, ticket);

  System.out.println("Message 2 before encrypting with K-alice: "+Arrays.toString(message));

    // encrypting msg-2 with alice key K-alice.
      byte[] textEncrypted = Alice.encryptCipherKA.doFinal(message);
      desCipher.init(Cipher.DECRYPT_MODE, Alice.KAlice_KDC);

      List<Object> byteArrayWrapper = new ArrayList<>();

for (int i = 0; i < textEncrypted.length; i++)
{
    byteArrayWrapper.add(textEncrypted[i]);
}

     
 return byteArrayWrapper;

      
}
   catch(IllegalBlockSizeException e){
    e.printStackTrace();
  }catch(BadPaddingException e){
    e.printStackTrace();
  } catch (InvalidKeyException e) {
    e.printStackTrace();
  } 

return null;


    }

// This function creates ticket for bob
    private byte[] generateTicketForBob(SecretKey Kab) 
    {
      String alice="Alice";
      byte[] b2=alice.getBytes();
      List<Byte> byteList=new ArrayList<>();

      byte[] aliceEncrypt, KabEncrypt;
      byte[] resultEncrypt;

    for (byte b : b2) {
      byteList.add(b);
  }
    // converting b2 array into Byte[] form so that it can be passed as an object to another program.
  byte[] aliceMsg = new byte[byteList.size()];
for (int i = 0; i < byteList.size(); i++) {
  aliceMsg[i] = byteList.get(i);
}
  try {
    aliceEncrypt = Bob.encryptCipherKB.doFinal(aliceMsg);
    Cipher c=Bob.encryptCipherKB;
c.init(Cipher.WRAP_MODE, Bob.KBob_KDC);
    KabEncrypt=c.wrap(Kab);


  resultEncrypt= Arrays.copyOf(KabEncrypt, KabEncrypt.length + aliceEncrypt.length);
  System.arraycopy(aliceEncrypt, 0, resultEncrypt, KabEncrypt.length, aliceEncrypt.length);

return resultEncrypt;
  } catch (IllegalBlockSizeException | BadPaddingException e) {
    e.printStackTrace();
  } catch (InvalidKeyException e) {
    e.printStackTrace();
  }


      return null;
    }

    //This method generates secret key K-ab 

    private SecretKey generateSecretKeyAliceBob() {
      KeyGenerator keygenerator; SecretKey sk;
      try {
        keygenerator = KeyGenerator.getInstance("TripleDES");
        sk= keygenerator.generateKey();
        return sk;
      } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
      }
       
return null;
      
    }
    // concatenating all the messages so that it can be encrypted afterwards
    public static byte[] concatenate(Object... arrays) {
      int totalLength = 0;
      for (Object array : arrays) {
          if (array instanceof byte[]) {
              totalLength += ((byte[]) array).length;
          } else if (array instanceof String) {
              totalLength += ((String) array).getBytes(StandardCharsets.UTF_8).length;
          } else if (array instanceof Long) {
              totalLength += Long.BYTES;
          } else {
              throw new IllegalArgumentException("Unsupported type: " + array.getClass());
          }
      }
      byte[] result = new byte[totalLength];
      int currentIndex = 0;
      for (Object array : arrays) {
          if (array instanceof byte[]) {
            
              byte[] byteArray = (byte[]) array;
              System.arraycopy(byteArray, 0, result, currentIndex, byteArray.length);
              currentIndex += byteArray.length;
          } else if (array instanceof String) {
            // System.out.println("string");
            // System.out.println("curr ind: "+currentIndex);

              byte[] byteArray = ((String) array).getBytes(StandardCharsets.UTF_8);
              System.arraycopy(byteArray, 0, result, currentIndex, byteArray.length);
              currentIndex += byteArray.length;

          } else if (array instanceof Long) 
          {   
              long value = (long) array;
              for (int i = 0; i < Long.BYTES; i++) 
              {
                  result[currentIndex++] = (byte) (value >> (i * 8));
              }
          } else {
              throw new IllegalArgumentException("Unsupported type: " + array.getClass());
          }
      }
      return result;
  }

}
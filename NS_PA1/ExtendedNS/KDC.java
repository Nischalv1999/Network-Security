package ExtendedNS;
import java.util.List;
import java.util.concurrent.CountDownLatch;
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

   CountDownLatch latch;

  public KDC(CountDownLatch latch) {
   this.latch = latch;
 }
 
 @Override
    CountDownLatch getLatch() {
      return this.latch;
    }
    //Getting port number of KDC
    public Integer getPort() {
        return PORT;
      }

  //Returns the msg to the Server that KDC wants to send to the client.
    @Override
    List<Object> getServerMsg(List<Object> listOfMessages) 
    {
      // TODO Auto-generated method stub

try{
      Cipher desCipher=Alice.encryptCipherKA;
System.out.println("KDC says: Recieved request from Alice");
System.out.println("KDC says: Generating Secret Key K-ab and ticket to Bob");
      // SecretKey KAlice_KDC=(SecretKey) listOfMessages.get(0);
      long N1=(long)listOfMessages.get(0);
      String bob="Bob";

      SecretKey Kab=generateSecretKeyAliceBob();

byte[] ticket=generateTicketForBob(listOfMessages,Kab);





      ArrayList<Byte> byteList=new ArrayList<Byte>();

      System.out.println("--------------------------------------------------------------------------------------------------------");
    System.out.println("Message 4: KDC ---> Alice is as follows: ");
    System.out.println("K-alice(N1, Bob, K-ab, Ticket-to-Bob), where Ticket-to-Bob= K-bob(K-ab, Alice, Nb) ");
    System.out.println("--------------------------------------------------------------------------------------------------------");

 String encodedKab=(String)Base64.getEncoder().encodeToString(Kab.getEncoded());

 // concatenating all the messages and encrypting.
  byte[] message = concatenate(N1, bob.getBytes(StandardCharsets.UTF_8), encodedKab, ticket);

  System.out.println("Message 4 before encryption:  "+Arrays.toString(message));

      // encrypting msg-2 with alice key K-alice.
      byte[] textEncrypted = Alice.encryptCipherKA.doFinal(message);

      desCipher.init(Cipher.DECRYPT_MODE, Alice.KAlice_KDC, Alice.ivectorSpecv);

      List<Object> byteArrayWrapper = new ArrayList<>();

for (int i = 0; i < textEncrypted.length; i++)
{
    byteArrayWrapper.add(textEncrypted[i]);
}

     // Decrypt the text
      // byte[] textDecrypted = desCipher.doFinal(textEncrypted);

      // System.out.println("Text after Decrypting: "+Arrays.toString(textDecrypted));
 return byteArrayWrapper;

      
}
   catch(IllegalBlockSizeException e){
    e.printStackTrace();
  }catch(BadPaddingException e){
    e.printStackTrace();
  } catch (InvalidKeyException e) {
    // TODO Auto-generated catch block
    e.printStackTrace();
  } catch (InvalidAlgorithmParameterException e) {
    // TODO Auto-generated catch block
    e.printStackTrace();
  } 

return null;


    }

// This function creates ticket for bob
    private byte[] generateTicketForBob(List<Object> listOfMessages, SecretKey Kab) 
    {
      String alice="Alice";
      byte[] b2=alice.getBytes();
      List<Byte> byteList=new ArrayList<>();

      byte[] aliceEncrypt, KabEncrypt;
      byte[] NbEncryptKBob=new byte[Long.BYTES];

      byte[] resultEncrypt;


      
        NbEncryptKBob= convertObjectToByte((Byte[])listOfMessages.get(1));
      
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


   resultEncrypt = new byte[KabEncrypt.length + aliceEncrypt.length + NbEncryptKBob.length];
  System.arraycopy(KabEncrypt, 0, resultEncrypt, 0, KabEncrypt.length);
  System.arraycopy(aliceMsg, 0, resultEncrypt, KabEncrypt.length, aliceMsg.length);
  System.arraycopy(NbEncryptKBob, 0, resultEncrypt, KabEncrypt.length + aliceMsg.length, NbEncryptKBob.length);



  System.out.println("resultEncrypt ticket in KDC: "+resultEncrypt);
return resultEncrypt;
  } catch (IllegalBlockSizeException | BadPaddingException e) {
    // TODO Auto-generated catch block
    e.printStackTrace();
  } catch (InvalidKeyException e) {
    // TODO Auto-generated catch block
    e.printStackTrace();
  }


      return null;
    }

      // convertObjectToByte converts Byte[] object to byte[]
    public static byte[] convertObjectToByte(Byte[] bytes) 
    {
      byte[] byteArray = new byte[bytes.length];

for (int i = 0; i < bytes.length; i++) {
    byteArray[i] = bytes[i];
}
return byteArray;
    }

    //This method generates secret key K-ab 
    private SecretKey generateSecretKeyAliceBob() {
      KeyGenerator keygenerator; SecretKey sk;
      try {
        keygenerator = KeyGenerator.getInstance("TripleDES");
        sk= keygenerator.generateKey();
        return sk;
      } catch (NoSuchAlgorithmException e) {
        // TODO Auto-generated catch block
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
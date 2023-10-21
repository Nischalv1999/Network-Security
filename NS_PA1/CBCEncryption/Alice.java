package CBCEncryption;

import java.io.*;
import java.lang.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Alice implements Runnable {
  public static Integer PORT = 8879;

  static KeyGenerator keygenerator;
  static Cipher encryptCipherKA;
  static SecretKey KAlice_KDC;
  static SecretKey Kab;
  byte[] ticket;
  Socket clientSocketTrudy;
  byte[] textDecrypted;

  ArrayList<Object> out_msg;
  Random rand = new Random();

 static long N1,N2;
  
 static byte[] ivBytes = new byte[]{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
static IvParameterSpec ivectorSpecv = new IvParameterSpec(ivBytes);

// Generating K-alice key and initialising Cipher

  static {
    try {
      keygenerator = KeyGenerator.getInstance("TripleDES");
      KAlice_KDC = keygenerator.generateKey();
      encryptCipherKA = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");

      encryptCipherKA.init(Cipher.ENCRYPT_MODE, KAlice_KDC, ivectorSpecv);

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

  
// a.start() in Multithreading class runs this function

  public void run() {

    System.out.println("Alice sending (encrypted) N2 with value: "+N2+" to Bob");

    Socket clientSocket = null;
    out_msg = new ArrayList<Object>();
    N1 = rand.nextLong();
    
    // Getting Msg-2 from KDC 
    List<Object> msg2 = msgFromKDC(out_msg, clientSocket);
       
    //Decrypting the msg-2 recieved from KDC

    decprytMsg2(msg2);
    try {
            //sending msg-2 to Trudy(Basically Trudy is eavsdropping here)

      sendMsg2ToTrudy();
    } catch (IOException e) {
      e.printStackTrace();
    }

  }

  private void sendMsg2ToTrudy() throws IOException {

    List<Object> msgToTrudy=new ArrayList<>();
    clientSocketTrudy = new Socket("localhost", 8869);
        
    //generate N2 nonce and send to Trudy
    N2=rand.nextLong();

      //Encrypt N2 with K-ab

    byte[] encryptN2=encryptNonce(N2);
   

    Byte[] encryptN2Object = new Byte[encryptN2.length];

    for (int i = 0; i < encryptN2.length; i++) {
      encryptN2Object[i] = Byte.valueOf(encryptN2[i]);
  }
  Byte[] encryptTicketObject = new Byte[ticket.length];

    for (int i = 0; i < ticket.length; i++) {
      encryptTicketObject[i] = Byte.valueOf(ticket[i]);
  }
  // adding msg-3 and sending to Bob 
    msgToTrudy.add(encryptN2Object);
    msgToTrudy.add(encryptTicketObject);
    msgToTrudy.add(Kab);
   
      // create an object output stream from the output stream so we can send an object through it
      ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocketTrudy.getOutputStream());
      objectOutputStream.writeObject(msgToTrudy);

  }

  public static byte[] encryptNonce(long N2) 
  {
    Cipher CipherKANonce;
// System.out.println("N2 in alice: "+N2);
   try {
    CipherKANonce = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
    CipherKANonce.init(Cipher.ENCRYPT_MODE, Kab, ivectorSpecv);
    byte[] result=new byte[Long.BYTES];
              for (int i = 0; i < Long.BYTES; i++) 
              {
                  result[i] = (byte) (N2 >> (i * 8));
              }

    byte[] encryptedNonce = CipherKANonce.doFinal(result);
// System.out.println("encryptNonce length: "+encryptedNonce.length);
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

  private void decprytMsg2(List<Object> msg2) 
  {

    byte[] byteArray = new byte[msg2.size()];
    for(int i=0;i<msg2.size();i++)
    {
      byteArray[i]=(byte) msg2.get(i);
    }
    Cipher desCipher=Alice.encryptCipherKA;
    try {
      desCipher.init(Cipher.DECRYPT_MODE, Alice.KAlice_KDC, ivectorSpecv);

       this.textDecrypted = desCipher.doFinal(byteArray);
       System.out.println("Message 2 after decrypting with K-alice: "+Arrays.toString(textDecrypted));


      byte[] nonceN1=new byte[Long.BYTES];

      int currIndex=0;
      for(currIndex=0;currIndex<Long.BYTES;currIndex++)
      {
          nonceN1[currIndex]=textDecrypted[currIndex];
      }
      long result = 0; //result is the N1 after decrypting
      for (int i = 0; i < nonceN1.length; i++) {
        result |= ((long) nonceN1[i] & 0xFF) << (8 * i);
      }
 
      currIndex+=3;

      byte[] byteArray1 = new byte[32];

      for(int i=0;i<32;i++,currIndex++)
      {
          byteArray1[i]= textDecrypted[currIndex];
      }

      String originalString = new String(byteArray1, StandardCharsets.UTF_8);

        byte[] decodedKey = Base64.getDecoder().decode(originalString);
// rebuild key using SecretKeySpec
this.Kab= new SecretKeySpec(decodedKey, 0, decodedKey.length, "TripleDES");

this.ticket = new byte[40];

for(int i=0;i<40;i++,currIndex++)
{
  this.ticket[i]= textDecrypted[currIndex];
}
// System.out.println("Ticket after decoding: "+Arrays.toString(this.ticket));



    } catch (InvalidKeyException e) 
    {
      e.printStackTrace();
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
    } catch (BadPaddingException e) {
      e.printStackTrace();
    } catch (InvalidAlgorithmParameterException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }



  }

  

  private List<Object> msgFromKDC(ArrayList<Object> out_msg2, Socket clientSocket) {
    try {

      out_msg.add(N1);
      out_msg.add("Alice wants to talk to Bob");
      long decryptedN1=N1;
      clientSocket = new Socket("localhost", 8899);
      // create an object output stream from the output stream so we can send an
      // object through it
      ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
      objectOutputStream.writeObject(out_msg);

      ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream());
      List<Object> listOfMessages = (List<Object>) objectInputStream.readObject();

      System.out.println("--------------------------------------------------------------------------------------------------------");

      System.out.println("Message 2: KDC---->Alice is as follows:");
      System.out.print("N1 encrypted with K-alice: "); 
      System.out.println("Bob");
      System.out.println("Secret Key K-ab");
      System.out.println("Ticket to Bob");
      System.out.println("--------------------------------------------------------------------------------------------------------");

      System.out.println("Alice decrypting N1 and check its value");
      if(N1==decryptedN1)
      {
        System.out.println("Alice says: KDC authenticated and recieved K-ab and ticket to Bob successfully");
      }

      clientSocket.close();
      objectOutputStream.close();
      objectInputStream.close();

      return listOfMessages;

    } catch (UnknownHostException e) {
      System.err.println("Unknown host: localhost");
      System.exit(1);
    } catch (IOException e) {
      System.err.println("Run the file again!!!");
      System.exit(1);
    } catch (ClassNotFoundException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    return null;
  }

  public Integer getPort() {
    return PORT;
  }


}
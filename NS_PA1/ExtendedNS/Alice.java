package ExtendedNS;

import java.io.*;
import java.lang.*;
import java.util.*;

import java.util.concurrent.CountDownLatch;
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

  // ivectorSpecv is the initial vector for 3Des encryption in CBC mode
  static byte[] ivBytes = new byte[]{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
  static IvParameterSpec ivectorSpecv = new IvParameterSpec(ivBytes);

  ArrayList<Object> out_msg;
  Random rand = new Random();

  static long N1,N2;

   CountDownLatch latch;

 public Alice(CountDownLatch latch) {
  this.latch = latch;
}

// Generating key K-alice
  static {
    try {
      keygenerator = KeyGenerator.getInstance("TripleDES");
      KAlice_KDC = keygenerator.generateKey();
      encryptCipherKA = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");

      encryptCipherKA.init(Cipher.ENCRYPT_MODE, KAlice_KDC,ivectorSpecv);

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

  
  // This function is executed when Alice's thread starts running.
  public void run() {
    Socket clientSocket = null;
    out_msg = new ArrayList<Object>();
    //N1 is the nonce
    N1 = rand.nextLong();
    System.out.println("--------------------------------------------------------------------------------------------------------");
    System.out.println("Message 1: Alice ---> Bob");
    System.out.println("Alice wants to talk to Bob");
    System.out.println("--------------------------------------------------------------------------------------------------------");

    //Getting msg2 from Bob
    List<Object> msg2 = msg2FromBob(out_msg, clientSocket);
    msg2.add(1, "Alice Wants Bob");
    msg2.add(0,N1);

    //sending msg3 to KDC and retrieving Msg-4
    List<Object> msg4=sendMsg3ToKDC(msg2);

    List<Object> msg6FromBob;
    //Decrypting msg-4
    decprytMsg3(msg4);

      //sending msg5 to Bob and getting msg6
      msg6FromBob=sendMsg5ToBob();
    
//sending msg7 to Bob.
sendMsg7ToBob(msg6FromBob);

  }

   private void sendMsg7ToBob(List<Object> msg6FromBob) 
  {
    try {
      // convertObjectToByte converts Byte[] object to byte[]
    byte[] encryptedN2Minus1= KDC.convertObjectToByte((Byte[])msg6FromBob.get(0));
    
   long decryptedN2Minus1= Bob.decryptNonce(encryptedN2Minus1, Kab);
  
   byte[] encryptedN3=KDC.convertObjectToByte((Byte[])msg6FromBob.get(1));
   long decryptedN3= Bob.decryptNonce(encryptedN3, Kab);
   System.out.println("Alice: decrypting Message 6 sent by Bob.......");
   System.out.println("N2 calculated from N2-1 that was recieved from Bob: ");
   System.out.println(decryptedN2Minus1+1);
   System.out.println("N3 from alice: "+decryptedN3);

   //Checking N2 recieved from Bob and N2 stored at Alice to authenticate Bob
   if(decryptedN2Minus1+1==N2)
   {
      System.out.println("Alice says: Bob Authenticated Successfully");
   }

   long N3Minus1=decryptedN3-1;

   Byte[] encryptedN3Minus1=Bob.convertByteToObject(Bob.encryptNonce(N3Minus1,Kab));
   List<Object> msg7ToBob=new ArrayList<>();

   //Adding the Msg-7 (K-ab(N3-1)) to the object msg7ToBob and sending to Bob 
   msg7ToBob.add(new String("LastMessage"));
   msg7ToBob.add(encryptedN3Minus1);

   Socket clientSocketBob;
  
   System.out.println("--------------------------------------------------------------------------------------------------------");
   System.out.println("Message 7: Alice ---> Bob is as follows: ");
   System.out.println("K-ab(N3-1)");
   System.out.println("--------------------------------------------------------------------------------------------------------");


   // Establishing connection with Bob
    clientSocketBob = new Socket("localhost", 8889);
    ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocketBob.getOutputStream());
      objectOutputStream.writeObject(msg7ToBob);

  } catch (IOException e) {
    e.printStackTrace();
  }
      
  }

  private List<Object> sendMsg3ToKDC(List<Object> msg2) 
  {
   Socket clientSocket1;
  try {

    System.out.println("--------------------------------------------------------------------------------------------------------");
    System.out.println("Message 3: Alice ---> KDC is as follows: ");
    System.out.println("N1");
    System.out.println("Alice wants Bob");
    System.out.println("Encrypted Nb(which was recieved from Bob)");
    System.out.println("--------------------------------------------------------------------------------------------------------");

// Establishing connection with KDC
    clientSocket1 = new Socket("localhost", 8899);
    // create an object output stream from the output stream so we can send an
      // object through it
      ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket1.getOutputStream());
      objectOutputStream.writeObject(msg2);

      ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket1.getInputStream());
      List<Object> listOfMessages = (List<Object>) objectInputStream.readObject();

              return listOfMessages;
  } catch (IOException e) {
    e.printStackTrace();
  } catch (ClassNotFoundException e) {
    e.printStackTrace();
  }
      
    return null;
  }

  private List<Object> sendMsg5ToBob() {

    try {
      System.out.println("--------------------------------------------------------------------------------------------------------");
      System.out.println("Message 5: Alice ---> Bob is as follows: ");
      System.out.println("Ticket-to-Bob");
      System.out.println("K-ab(N2)");
      System.out.println("--------------------------------------------------------------------------------------------------------");


    List<Object> msgToTrudy=new ArrayList<>();
    // Establishing connection with Bob
    clientSocketTrudy = new Socket("localhost", 8889);

    // N2 is nonce
    N2=rand.nextLong();
    System.out.println("N2 created by Alice: "+N2);

   
    byte[] encryptN2=encryptNonce(N2);
   

    //converting byte[] to Byte[] object
    Byte[] encryptN2Object = new Byte[encryptN2.length];

    for (int i = 0; i < encryptN2.length; i++) {
      encryptN2Object[i] = Byte.valueOf(encryptN2[i]);
  }
  Byte[] encryptTicketObject = new Byte[ticket.length];

    for (int i = 0; i < ticket.length; i++) {
      encryptTicketObject[i] = Byte.valueOf(ticket[i]);
  }
    msgToTrudy.add(encryptN2Object);
    msgToTrudy.add(encryptTicketObject);
    System.out.println("K-ab in Alice: "+Kab);
    msgToTrudy.add(Kab);
    
      // create an object output stream from the output stream so we can send an object through it
      ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocketTrudy.getOutputStream());
      objectOutputStream.writeObject(msgToTrudy);

      ObjectInputStream objectInputStream = new ObjectInputStream(clientSocketTrudy.getInputStream());
      List<Object> msg6FromBob;
            
            msg6FromBob = (List<Object>) objectInputStream.readObject();

return msg6FromBob;
     } 
            catch (ClassNotFoundException e) {
              e.printStackTrace();
            } catch (UnknownHostException e) {
              // TODO Auto-generated catch block
              e.printStackTrace();
            } catch (IOException e) {
              // TODO Auto-generated catch block
              e.printStackTrace();
            }

return null;
  }
// This function encrypts Nonce
  public static byte[] encryptNonce(long N2) 
  {
    Cipher CipherKANonce;
   try {
    CipherKANonce = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
    CipherKANonce.init(Cipher.ENCRYPT_MODE, Kab,ivectorSpecv);
    byte[] result=new byte[Long.BYTES];
              for (int i = 0; i < Long.BYTES; i++) 
              {
                  result[i] = (byte) (N2 >> (i * 8));
              }

    byte[] encryptedNonce = CipherKANonce.doFinal(result);

    return encryptedNonce;
  } 

  catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
    e.printStackTrace();
  } catch (InvalidKeyException e) {
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
  return null;

  }

  private void decprytMsg3(List<Object> msg2) 
  {

    byte[] byteArray = new byte[msg2.size()];
    for(int i=0;i<msg2.size();i++)
    {
      byteArray[i]=(byte) msg2.get(i);
    }

    Cipher desCipher=Alice.encryptCipherKA;
    try {
      desCipher.init(Cipher.DECRYPT_MODE, Alice.KAlice_KDC,Alice.ivectorSpecv);

      // decrypting msg-4
       this.textDecrypted = desCipher.doFinal(byteArray);
      System.out.println("Message 4 after decrypting at Alice: "+Arrays.toString(textDecrypted));

      byte[] nonceN1=new byte[Long.BYTES];

      // Storing all the individual msgs in the msg-4 into separate array  
      int currIndex=0;
      for(currIndex=0;currIndex<Long.BYTES;currIndex++)
      {
          nonceN1[currIndex]=textDecrypted[currIndex];
      }
      //result is the N1 after decrypting
      long result = 0; 
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
        // Storing the key K-ab recieved from KDC
this.Kab= new SecretKeySpec(decodedKey, 0, decodedKey.length, "TripleDES");

this.ticket = new byte[56];

for(int i=0;i<56;i++,currIndex++)
{
  this.ticket[i]= textDecrypted[currIndex];
}



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

  private List<Object> msg2FromBob(ArrayList<Object> out_msg2, Socket clientSocket) {
    try {

      out_msg.add("Alice wants to talk to Bob");

      clientSocket = new Socket("localhost", 8889);
      // create an object output stream from the output stream so we can send an
      // object through it
      ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
      objectOutputStream.writeObject(out_msg);

      ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream());
      List<Object> listOfMessages = (List<Object>) objectInputStream.readObject();
              listOfMessages.forEach((msg)-> System.out.println("Alice says: Message recieved from Bob : "+ Arrays.toString((Byte[]) msg)));

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
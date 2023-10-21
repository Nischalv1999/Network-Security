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

// Trudy class to impersonate Alice
public class Trudy implements Runnable 
{
  public Integer PORT = 8869;

  static KeyGenerator keygenerator;
  static Cipher encryptCipherKA;
  static SecretKey KAlice_KDC;
  static SecretKey Kab;

   Socket clientAliceSocket;
   ArrayList<Object> out_msg;
   Random rand = new Random();
   ServerSocket serverSocket ; 
   List<Object> finalMsgFromBob;

  // Runs this function when Trudy thread starts.
  public void run() {
   
    try {
      serverSocket = new ServerSocket(this.PORT);

      // Initially getting msgs from Alice
      clientAliceSocket = serverSocket.accept();
      ObjectInputStream objectInputStream = new ObjectInputStream(clientAliceSocket.getInputStream());

            List<Object> listOfMessagesAlice = (List<Object>) objectInputStream.readObject();

            
           Socket clientSocketBob = new Socket("localhost", 8889);
      // create an object output stream from the output stream so we can send an
      // object through it
      ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocketBob.getOutputStream());
      objectOutputStream.writeObject(listOfMessagesAlice);

      ObjectInputStream objectInputStreamBob = new ObjectInputStream(clientSocketBob.getInputStream());

      List<Object> listOfMessagesBob = (List<Object>) objectInputStreamBob.readObject();

      System.out.println("--------------------------------------------------------------------------------------------------------");
      System.out.println("Message 4: Bob ---> Alice is a follows:");
      System.out.println("N2-1 and N3 encrypted with secret key K-ab");
      System.out.println("--------------------------------------------------------------------------------------------------------");

      System.out.println("Trudy eavesdropping had stored messages 3 and 4");

        // performs replay attack
        performReplayAttackToBob(listOfMessagesBob);
        
        // resume original session between Bob and Trudy.
        resumeOriginalSession(finalMsgFromBob);



      clientAliceSocket.close();
      objectInputStream.close();
      objectOutputStream.close();
      serverSocket.close();
      clientSocketBob.close();

    } catch (IOException e) {
      e.printStackTrace();
    } catch (ClassNotFoundException e) {
      e.printStackTrace();
    }
   
  }

 
  private void resumeOriginalSession(List<Object> finalMsgFromBob2)
  {
    Thread b = new Thread(new Bob());
    b.start();
    try {
      Thread.sleep(1000);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    

      try {

Socket clientSocketBob = new Socket("localhost", 8889);
// create an object output stream from the output stream so we can send an
// object through it

//sending msg K-ab(N3-1) to Bob
ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocketBob.getOutputStream());
objectOutputStream.writeObject(finalMsgFromBob2);


ObjectInputStream objectInputStreamBob = new ObjectInputStream(clientSocketBob.getInputStream());

List<Object> msgs = (List<Object>) objectInputStreamBob.readObject();

      }
       catch (IOException e) {
        e.printStackTrace();
      } catch (ClassNotFoundException e) {
        e.printStackTrace();
      }

  }


  private void performReplayAttackToBob(List<Object> listOfMessagesBob)
  {
    System.out.println("Trudy opened another session with Bob and performs Reflection Attack ");

    // running Bob thread

    Thread b = new Thread(new Bob());
    b.start();
    try {
      Thread.sleep(1000);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    System.out.println("Trudy sending N3 encrypted recieved from Bob in the original session");

  

List<Object> msgToBob=new ArrayList<>();

msgToBob.add(new String("Trudy"));

Byte[] temp=(Byte[])listOfMessagesBob.get(0);
Byte[] N3nonce=new Byte[16];
for(int i=0,j=8;i<16;i++,j++)
{
  N3nonce[i]=temp[j];
}

msgToBob.add(N3nonce);
      try {

Socket clientSocketBob = new Socket("localhost", 8889);
// create an object output stream from the output stream so we can send an
// object through it
ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocketBob.getOutputStream());
objectOutputStream.writeObject(msgToBob);


ObjectInputStream objectInputStreamBob = new ObjectInputStream(clientSocketBob.getInputStream());

List<Object> msgs = (List<Object>) objectInputStreamBob.readObject();
       msgs.forEach((msg)-> System.out.println("Trudy says: Encrypted N3-1 recieved from Bob: "+Arrays.toString((Byte[]) msg)));

       msgs.add(0,new String("TrudyLast"));
       finalMsgFromBob=msgs;
      }
       catch (IOException e) {
        e.printStackTrace();
      } catch (ClassNotFoundException e) {
        e.printStackTrace();
      }
  }

//returning port number
  public Integer getPort() {
    return PORT;
  }

  
}
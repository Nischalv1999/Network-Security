

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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;


public class BobClient implements Runnable {
    

  public static Integer PORT = 8869;

  static KeyGenerator keygenerator;
  static Cipher encryptCipherKA;
  static SecretKey KAlice_KDC;
  static SecretKey Kab;
  byte[] ticket;
  Socket clientSocketTrudy;
  byte[] textDecrypted;
  


Random rand = new Random();

 static long N1,N2;
  

// Generating K-alice key and initialising Cipher
  static {
    
  }
  
// a.start() in Multithreading class runs this function
  public void run() {
    
    try {
        Socket clientSocket = null;
        Socket socket = new Socket("localhost", 8899);
        List<Object> msg=new ArrayList<>();
        // Send a message requesting a certificate
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        msg.add("I am Bob and I want a certificate");
        objectOutputStream.writeObject(msg);
  
        // Receive the certificate from the CA
        InputStream in = socket.getInputStream();
            byte[] fileBytes = new byte[1024];
            FileOutputStream fileOut = new FileOutputStream("ServerPrograms/bob.crt");
            int bytesRead = in.read(fileBytes, 0, fileBytes.length);
            fileOut.write(fileBytes, 0, bytesRead);
            fileOut.close();
            in.close();
            socket.close();
            System.out.println("Bob says: Received the certificate from the CA");
            
            

    

    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } 
    
  }

  
    //getting the port number
  public Integer getPort() {
    return PORT;
  }




}

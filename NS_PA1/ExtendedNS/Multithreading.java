package ExtendedNS;
import java.lang.*;
import java.util.*;
import java.util.concurrent.CountDownLatch;

// This class is used to run different threads on Trudy, Alice, KDC and Bob
public class Multithreading {
    
   static CountDownLatch latch = new CountDownLatch(3);

    public static void main(String[] args)
    {

        Alice alice = new Alice(latch);
    Bob bob = new Bob(latch);
    KDC kdc = new KDC(latch);

    Thread a = new Thread(alice);

    Thread b = new Thread(bob);
    Thread k = new Thread(kdc);


    // b.start();
    k.start();
    try {
        Thread.sleep(100);
    } catch (InterruptedException e) {
        e.printStackTrace();
    }
    a.start();
    b.start();
    }
}

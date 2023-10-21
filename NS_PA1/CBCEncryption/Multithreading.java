package CBCEncryption;
import java.lang.*;
import java.util.*;

// This class is used to run different threads on Trudy, Alice, KDC and Bob
public class Multithreading {
    
    public static void main(String[] args)
    {
        Alice alice = new Alice();
    Bob bob = new Bob();
    KDC kdc = new KDC();
    Trudy trudy =new Trudy();

    Thread a = new Thread(alice);

    Thread b = new Thread(bob);
    Thread k = new Thread(kdc);
        Thread t = new Thread(trudy);


    // b.start();
    k.start();
    try {
        Thread.sleep(100);
    } catch (InterruptedException e) {
        e.printStackTrace();
    }
    t.start();
    a.start();
    b.start();
    }
}

package rsa;

import java.util.logging.Logger;
import java.util.logging.Level;
import java.io.IOException;


public class ManualRSA {

	public static void main(String[] args) {
		
		RSAEncDec rsa = new RSAEncDec();
		String data = null;
		
		System.out.println("RSA ENCRYPTION PROCESS");
		System.out.println("");
		
		try {
			System.out.println("Prime Value (p): 47");
			int p = 47;
			
			System.out.println("Prime Value (p): 71");
			int q = 71;
			
			System.out.println("Public Key Value (e): 79");
			int e = 79;
			
			rsa.setKey(p, q, e);
			
			System.out.println();
			System.out.println("Message (M) = HARI INI");
			
			data = rsa.encryptText("HARI INI");
			
			rsa.decryptText(data);
			
		}catch(IOException ex){
			Logger.getLogger(ManualRSA.class.getName()).log(Level.SEVERE, null, ex);
		}catch(Exception ex){
			Logger.getLogger(ManualRSA.class.getName()).log(Level.SEVERE, null, ex);
		}

	}

}

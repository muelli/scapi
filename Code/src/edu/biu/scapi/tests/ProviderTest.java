/**
 * Project: scapi.
 * Package: edu.biu.scapi.tests.
 * File: ProviderTest.java.
 * Creation date Apr 7, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.tests;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.logging.Level;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.tools.Provider.ScapiProvider;

/**
 * @author LabTest
 *
 */
public class ProviderTest {

	/**
	 * main
	 * @param args
	 * @throws NoSuchProviderException 
	 */
	public static void main(String[] args) throws NoSuchProviderException {

		Security.addProvider(new ScapiProvider());
		MessageDigest sha1 = null;
		try {
			sha1 = MessageDigest.getInstance("SHA1", "SCAPI");
		} catch (NoSuchAlgorithmException e) {
			
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		
		sha1.update(toByteArray("abc"));
		
		byte[] output = Hex.decode("a9993e364706816aba3e25717850c26c9cd0d89d");
		byte[] out = sha1.digest();

		
	}
	
	/**
	 * 
	 * toByteArray - from ASCII to byte array.
	 * @param input - input string
	 * @return resulted byte array.
	 */
	private static byte[] toByteArray(String input)
    {
		//the returned bytes arrat will have the same size as the input string since we translate from ASCII
        byte[] bytes = new byte[input.length()];
        
        //translate each character
        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)input.charAt(i);
        }
        
        return bytes;
    }

}

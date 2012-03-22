package edu.biu.scapi.tests.primitives;

import java.io.PrintWriter;
import java.security.InvalidKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.prf.AES;

/**
 * This class tests the performance and correctness of any implemented AES algorithm.
 * The test vectors are taken from http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class AESTest extends PrpTest {
	
	/**
	 * Sets the given AES object, adds data for the test vectors.
	 */
	public AESTest(AES aes) {
		super(aes);
		

		//AES 128
		addData(Hex.decode("00112233445566778899aabbccddeeff"),//input
				Hex.decode("69c4e0d86a7b0430d8cdb78070b4c55a"),//output
				Hex.decode("000102030405060708090a0b0c0d0e0f"));//key
		
		//AES 192
		addData(Hex.decode("00112233445566778899aabbccddeeff"),//input
				Hex.decode("dda97ca4864cdfe06eaf70a0ec0d7191"),//output
				Hex.decode("000102030405060708090a0b0c0d0e0f1011121314151617"));//key
		
		//AES 256
		addData(Hex.decode("00112233445566778899aabbccddeeff"),//input
				Hex.decode("8ea2b7ca516745bfeafc49904b496089"),//output
				Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));//key
		
		
		addDataInvertCompute(Hex.decode("00112233445566778899aabbccddeeff"),
				Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
	}
	
	/**
	 * Tests the case that the given initialization key has wrong size.
	 * The expected output is InvalidKeyException
	 * @param the output file
	 */
	protected void wrongKeySize(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//creates a SecretKey object out of the byte array key.
			SecretKey secretKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405"), "");
			
			//init the prf with the new secret key
			prf.init(secretKey);
			
		//the right result of this test is InvalidKeyException
		} catch (InvalidKeyException e) {
			testResult = "Success: The expected exception \"InvalidKeyException\" was thrown";
		//any other exception is wrong
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"InvalidKeyException\" was thrown";
		}
		
		//writes the result to the file
		file.println(prf.getAlgorithmName() + "," + provider + ",Wrong key size,Wrong behavior,,," + testResult);
		
	}
}
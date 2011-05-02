/**
 * 
 */
package edu.biu.scapi.primitives.crypto.kdf;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.primitives.crypto.prf.Hmac;


/** 
  * @author LabTest
 */
public class HKDF implements KeyDerivationFunction {
	
	private Hmac hmac;//the hmac to use. We assume that the hmac is initialized with a key and parameters

	/*
	 * We assume that the hmac is initialized with the required key.
	 */
	HKDF(Hmac hmac){
		
		this.hmac = hmac;
	}

	/**
	 * generates a new key from the source key material key.
	 * The pseudocode of thie function is as follows:
	 *   COMPUTE PRK = HMAC(XTS, SKM) [key=XTS, data=SKM]
	 *   Let t be the smallest number so that t * |H|>L where |H| is the HMAC output length
	 *   K(1) = HMAC(PRK,(CTXinfo,0)) [key=PRK, data=(CTXinfo,0)]
	 *   FOR i = 2 TO t
	 *     K(i) = HMAC(PRK,(K(i-1),CTXinfo,i)) [key=PRK, data=(K(i-1),CTXinfo,i)]
	 *   OUTPUT the first L bits of K(1),…,K(t)
	 *   
	 *   @param iv - CTXInfo 
	 * 
	 */
	public SecretKey generateKey(SecretKey key, int outLen, byte[] iv) {
		
		int hmacLength = hmac.getBlockSize();                           //the size of the output of the hmac.
		byte[] inBytes = key.getEncoded();                              //get the input key to work on
		byte[] outBytes = new byte[outLen];                             //the output key
		byte[] roundKey = new byte[hmacLength];							//PRK from the pseudocode
		int rounds = (int) Math.floor((float)outLen/(float)hmacLength); //the smallest number so that  hmacLength * rounds > outLen
		byte[] intermediateOutBytes = new byte[hmacLength];             //round result
		int currentInBytesSize;											//the size of the CTXInfo and also the round;
		
		if(iv!=null)
			currentInBytesSize = hmacLength + iv.length + 1;//the size of the CTXInfo and also the round;
		else//no CTXInfo
			currentInBytesSize = hmacLength + 1;//the size of the CTXInfo and also the round;
		
		byte[] currentInBytes = new byte[currentInBytesSize];
		Integer round;
		
		//copy the CTXInfo - iv
		if(iv!=null)
			System.arraycopy(currentInBytes, 0, iv, 0, currentInBytesSize - 1);
		
		//first compute the new key. The new key is the result of computing the hmac function.
		hmac.computetBlock(inBytes, 0, roundKey, 0);
		
		//init the hmac with the new key. From now on this is the key for all the rounds.
		hmac.init(new SecretKeySpec(roundKey, "HKDF"));
		
		//copy the roundKey which is also part of the input to the nexxt iteration
		System.arraycopy(roundKey, 0, intermediateOutBytes, 0, hmacLength);
			
		for(int i=0;i<rounds; i++){
			
			round = new Integer(i);//create the round integer for the date
			
			//copy the output of the last results
			System.arraycopy(intermediateOutBytes, 0, currentInBytes, 0, hmacLength);
			
			//copy the round integer to the date array 
			System.arraycopy(round.byteValue(), 0,currentInBytes , currentInBytesSize -1, 1);
			
			
			//operate the hmac to get the round output 
			try {
				hmac.computetBlock(currentInBytes, 0, currentInBytes.length, intermediateOutBytes, 0, hmacLength);
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			if(i==rounds - 1){//We fill the rest of the array with a portion of the last result.
				
				//copy the results to the output array
				System.arraycopy(intermediateOutBytes, 0,outBytes , 0, outLen - hmacLength*i);
			}
			else{
				//copy the results to the output array
				System.arraycopy(intermediateOutBytes, 0,outBytes , 0, hmacLength*i);
			}				
		}
		
		return new SecretKeySpec(outBytes, "HKDF");
	}

	public SecretKey generateKey(SecretKey key, int outLen) {

		//there is no auxiliary information send an empty iv.
		return generateKey(key, outLen, null);
	}

	public void generateKey(byte[] inKey, int inOff, int inLen, byte[] outKey,
			int outOff, int outLen) {

		//create a key out of the byte array and send it to the function generateKey(SecretKey key, int outLen, byte[] iv)
		
	}
}
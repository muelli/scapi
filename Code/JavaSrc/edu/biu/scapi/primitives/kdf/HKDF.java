/**
 * 
 * This is a key derivation function that has a rigorous justification as to its security
 */
package edu.biu.scapi.primitives.kdf;

import java.util.logging.Level;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.prf.Hmac;
import edu.biu.scapi.tools.Factories.PrfFactory;


/** 
  * @author LabTest
 */
public final class HKDF implements KeyDerivationFunction {
	
	private Hmac hmac;

	/*
	 * We assume that the hmac is initialized with the required key.
	 */
	HKDF(String hmac){
		
		this.hmac = (Hmac) PrfFactory.getInstance().getObject(hmac);
	}

	/**
	 * generates a new key from the source key material key.
	 * The pseudocode of this function is as follows:
	 * 
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
		byte[] intermediateOutBytes = new byte[hmacLength];             //round result K(i) in the pseudocode
		
		
		//first compute the new key. The new key is the result of computing the hmac function.
		try {
			//roundKey is now K(0)
			hmac.computeBlock(inBytes, 0, inBytes.length, roundKey, 0);
		} catch (IllegalBlockSizeException e) {//should not happen since the roundKey is of the right size.
			
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		
		//init the hmac with the new key. From now on this is the key for all the rounds.
		hmac.init(new SecretKeySpec(roundKey, "HKDF"));
		
		//calculate the first round
		//K(1) = HMAC(PRK,(CTXinfo,0)) [key=PRK, data=(CTXinfo,0)]
		firstRound(outBytes, iv, intermediateOutBytes, hmacLength);
		
		//calculate the next rounds
		//FOR i = 2 TO t
		//K(i) = HMAC(PRK,(K(i-1),CTXinfo,i)) [key=PRK, data=(K(i-1),CTXinfo,i)]
		nextRounds(outLen, iv, hmacLength, outBytes, 
				intermediateOutBytes);
		
		
		return new SecretKeySpec(outBytes, "HKDF");
	}

	/**
	 * Does the following part of the pseudo code:
	 * FOR i = 2 TO t
	 * K(i) = HMAC(PRK,(K(i-1),CTXinfo,i)) [key=PRK, data=(K(i-1),CTXinfo,i)]
	 * @param outLen
	 * @param iv the iv : ctxInfo
	 * @param hmacLength the size of the output of the hmac.
	 * @param outBytes the result of the overall computation
	 * @param intermediateOutBytes round result K(i) in the pseudocode
	 */
	private void nextRounds(int outLen, byte[] iv, int hmacLength,
			byte[] outBytes, byte[] intermediateOutBytes) {
		
		int rounds = (int) Math.ceil((float)outLen/(float)hmacLength); //the smallest number so that  hmacLength * rounds >= outLen
		
		int currentInBytesSize;	//the size of the CTXInfo and also the round;
		
		if(iv!=null)
			currentInBytesSize = hmacLength + iv.length + 1;//the size of the CTXInfo and also the round;
		else//no CTXInfo
			currentInBytesSize = hmacLength + 1;//the size without the CTXInfo and also the round;
		
		//the result of the current computation
		byte[] currentInBytes = new byte[currentInBytesSize];
		
		
		Integer roundIndex;
		//for rounds 2 to t 
		if(iv!=null)
			//in case we have an iv. put it (ctxInfo after the K from the previous round at position hmacLength.
			System.arraycopy(iv, 0, currentInBytes, hmacLength , iv.length);
				
		for(int i=2;i<=rounds; i++){
			
			roundIndex = new Integer(i-1);//create the round integer for the data
			
			//copy the output of the last results
			System.arraycopy(intermediateOutBytes, 0, currentInBytes, 0, hmacLength);
			
			//copy the round integer to the data array 
			System.arraycopy(roundIndex.byteValue(), 0,currentInBytes , currentInBytesSize -1, 1);
			
			
			//operate the hmac to get the round output 
			try {
				hmac.computeBlock(currentInBytes, 0, currentInBytes.length, intermediateOutBytes, 0);
			} catch (IllegalBlockSizeException e) {
				
				Logging.getLogger().log(Level.WARNING, e.toString());
			}
			
			if(i==rounds){//We fill the rest of the array with a portion of the last result.
				
				//copy the results to the output array
				System.arraycopy(intermediateOutBytes, 0,outBytes , hmacLength*(i-1), outLen - hmacLength*i);
			}
			else{
				//copy the results to the output array
				System.arraycopy(intermediateOutBytes, 0,outBytes , hmacLength*(i-1), hmacLength);
			}				
		}
	}

	/**
	 * 
	 * @param iv ctxInfo
	 * @param intermediateOutBytes round result K(1) in the pseudocode
	 * @param hmacLength the size of the output of the hmac.
	 * @param outBytes the result of the overall computation
	 */
	private void firstRound(byte [] outBytes, byte[] iv, byte[] intermediateOutBytes, int hmacLength) {
		Integer zero;
		//round 1
		byte[] firstRoundInput;//data for the creating K(1)
		if(iv!=null)
			firstRoundInput = new  byte[iv.length + 1];
		else
			firstRoundInput = new  byte[1];
		
		//copy the CTXInfo - iv
		if(iv!=null)
			System.arraycopy(iv, 0, firstRoundInput,0 , iv.length);
		
		zero = new Integer(0);//create the round integer for the date
		
		//copy the integer with zero to the data array 
		System.arraycopy(zero.byteValue(), 0,firstRoundInput , firstRoundInput.length -1, 1);
		
			
		//first compute the new key. The new key is the result of computing the hmac function.
		try {
			//calculate K(1) and put it in intermediateOutBytes.
			hmac.computeBlock(firstRoundInput, 0, firstRoundInput.length, intermediateOutBytes, 0);
		} catch (IllegalBlockSizeException e) {	
		
		}
		
		//copy the results to the output array
		System.arraycopy(intermediateOutBytes, 0,outBytes , 0, hmacLength);
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
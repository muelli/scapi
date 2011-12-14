/**
 * 
 */
package edu.biu.scapi.tools.Provider.Hash;

import java.security.MessageDigest;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.bc.BcSHA1;
import edu.biu.scapi.primitives.hash.bc.BcSHA224;
import edu.biu.scapi.primitives.hash.bc.BcSHA256;
import edu.biu.scapi.primitives.hash.bc.BcSHA384;
import edu.biu.scapi.primitives.hash.bc.BcSHA512;

/** 
 * 
 * @author LabTest
 *
 */
public abstract class MessageDigestProvider extends MessageDigest {
	
	private CryptographicHash crHash;//the underlying collision resistant hash

	/** 
	 * 
	 */
	public void engineReset() {
			}

	/** 
	 * 
	 */
	public int engineGetDigestLength() {
		
		return crHash.getHashedMsgSize();
	}

	/**
	 * 
	 */
	public byte[] engineDigest() {

		byte[] out = new byte[crHash.getHashedMsgSize()];
		
		try {
			crHash.hashFinal(out, 0);
		} catch (UnInitializedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return out;
		
	}

	/**
	 * 
	 */
	public void engineUpdate(byte[] in, int inOffset, int inLen) {
		
		try {
			crHash.update(in, inOffset, inLen);
		} catch (UnInitializedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void engineUpdate(byte in) {
		
		byte[] inputArray = new byte[1];
		
		inputArray[0] = in;

		try {
			crHash.update(inputArray, 0, inputArray.length);
		} catch (UnInitializedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	/**
	 * 
	 * @param crHash
	 */
	public MessageDigestProvider(CryptographicHash crHash) {
		
		super(crHash.getAlgorithmName());
		this.crHash = crHash;
		
	}
	
	static public class SHA1 extends MessageDigestProvider{

		/**
		 * 
		 */
		public SHA1() {
			super(new BcSHA1());
			// TODO Auto-generated constructor stub
		}
	}

	static public class SHA224 extends MessageDigestProvider{

		/**
		 * 
		 */
		public SHA224() {
			super(new BcSHA224());
			// TODO Auto-generated constructor stub
		}
	
	}
	
	static public class SHA256 extends MessageDigestProvider{

		/**
		 * 
		 */
		public SHA256() {
			super(new BcSHA256());
			// TODO Auto-generated constructor stub
		}
	
	}
	
	static public class SHA384 extends MessageDigestProvider{

		/**
		 * 
		 */
		public SHA384() {
			super(new BcSHA384());
			// TODO Auto-generated constructor stub
		}
	
	}
	
	static public class SHA512 extends MessageDigestProvider{

		/**
		 * 
		 */
		public SHA512() {
			super(new BcSHA512());
			// TODO Auto-generated constructor stub
		}
	
	}
}
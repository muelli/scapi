/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.midLayer.asymmetricCrypto.CramerShoupParameterSpec;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.*;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.ciphertext.CramerShoupCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.*;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.groupParams.ZpGroupParams;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA1;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.CryptographicHashFactory;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScCramerShoupDDH implements CramerShoupDDHEnc {
	
	private DlogGroup dlogGroup;
	private CryptographicHash hash;
	private CramerShoupPublicKey publicKey;
	private CramerShoupPrivateKey privateKey;
	private SecureRandom random;
	private boolean isInitialized;
	private CramerShoupParameterSpec params;

	/**
	 * Default constructor. It uses a Dlog group over Zp with p of size 1024 bits, and SHA1.
	 */
	public ScCramerShoupDDH() {
		super();
		this.dlogGroup = new CryptoPpDlogZpSafePrime();
		((CryptoPpDlogZpSafePrime) dlogGroup).init(1024);
		this.hash = new CryptoPpSHA1();
		
	}


	public ScCramerShoupDDH(DlogGroup dlogGroup, CryptographicHash hash) throws UnInitializedException {
		super();
		if(!(dlogGroup instanceof DDH)){
			throw new IllegalArgumentException("The Dlog group has to have DDH security level");
		}
		if(!dlogGroup.isInitialized()){
			throw new UnInitializedException("The Dlog group has to be already initialized");
		}
		if(!hash.isInitialized()){
			throw new UnInitializedException("The hash functions has to be already initialized");
		}
		
		//Everything is correct and initialized, then set the member variables and create object.
		this.dlogGroup = dlogGroup;
		this.hash = hash;
	}
	
	public ScCramerShoupDDH(String dlogGroupName, String hashName) throws FactoriesException{
		//Create the DlogGroup
		DlogGroup dlogGroup = DlogGroupFactory.getInstance().getObject(dlogGroupName);
		
		//The underlying dlog group must be DDH secure
		if (!(dlogGroup instanceof DDH)){
			throw new IllegalArgumentException("DlogGroup should have DDH security level");
		}
		this.dlogGroup = dlogGroup;
		
		//Createw the hash function object
		this.hash = CryptographicHashFactory.getInstance().getObject(hashName);
		 
	}
	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#init(java.security.PublicKey)
	 */
	/*@Override
	public void init(PublicKey publicKey) {
		init(publicKey, new SecureRandom());
	}
	*/
	

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#init(java.security.PublicKey, java.security.SecureRandom)
	 */
	/*@Override
	public void init(PublicKey publicKey, SecureRandom random) {
		init(publicKey, null, null, random);
	}
	*/
	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#init(java.security.PublicKey, java.security.PrivateKey)
	 */
	@Override
	public void init(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
		try{
			init(publicKey, privateKey, null);
		}catch (InvalidAlgorithmParameterException e){
			//Do nothing here, since passing a "null" parameter spec is legal in this case.
		}
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#init(java.security.PublicKey, java.security.PrivateKey, java.security.SecureRandom)
	 */
	/*@Override
	public void init(PublicKey publicKey, PrivateKey privateKey, SecureRandom random) {
		//Call init function will all arguments. Set the parameter spec argument to null.
		init(publicKey, privateKey, null, random);
	}
	*/

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#init(java.security.PublicKey, java.security.PrivateKey, java.security.spec.AlgorithmParameterSpec)
	 */
	/*@Override
	public void init(PublicKey publicKey, PrivateKey privateKey, AlgorithmParameterSpec params) {
		init(publicKey, privateKey, params, new SecureRandom());
	}
*/
	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#init(java.security.PublicKey, java.security.spec.AlgorithmParameterSpec)
	 */
	/*@Override
	public void init(PublicKey publicKey, AlgorithmParameterSpec params) {
		init(publicKey, params, new SecureRandom());
	}
*/
	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#init(java.security.PublicKey, java.security.spec.AlgorithmParameterSpec, java.security.SecureRandom)
	 */
	/*@Override
	public void init(PublicKey publicKey, AlgorithmParameterSpec params,
			SecureRandom random) {
		init(publicKey, null, params, random);
	}
	*/
	/**
	 * This function initialize an instance of this class.
	 * It checks the validity of the arguments and sets them.
	 * If any of the arguments is not valid it throws relevant exception.
	 * @param publicKey the public key has to be of type <link>CramerShoupPublicKey<link>
	 * @param privateKey the private key has to be of type <link>CramerShoupPrivateKey<link>
	 * @param params the parameters have to be of type <link>CramerShoupParameterSpec<link>
	 * @param random sets the source of randomness requested by the caller
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#init(java.security.PublicKey, java.security.PrivateKey, java.security.spec.AlgorithmParameterSpec, java.security.SecureRandom)
	 */
	@Override
	public void init(PublicKey publicKey, PrivateKey privateKey, AlgorithmParameterSpec params) throws  InvalidKeyException, InvalidAlgorithmParameterException{
		
		//public key should be Cramer Shoup public key
		if(!(publicKey instanceof ScCramerShoupPublicKey)){
			throw new InvalidKeyException("The public key must be of type CramerShoupPublicKey");
		}
		//Set the public key
		this.publicKey = (ScCramerShoupPublicKey) publicKey;

		//private key should be Cramer Shoup private key	
		if(privateKey == null){
			//If the private key in the argument is null then this instance's private key should be null.  
			this.privateKey = null;
		}else{
			if(!(privateKey instanceof ScCramerShoupPrivateKey)){
				throw new InvalidKeyException("The private key must be of type CramerShoupPrivatKey");
			}
			//Set the private key
			this.privateKey = (ScCramerShoupPrivateKey) privateKey;
		}
		
		//If the caller has not passed any parameters, then, initialize the secure random and the dlog group with default values. 
		if(params == null){
			initDlogDefault();
		}else{
			//Now we know that the caller wants this specific set of parameters: 
			//Make sure that params is of type  CramerShoupParameterSpec
			if(!(params instanceof CramerShoupParameterSpec)){
				throw new InvalidAlgorithmParameterException("the params argument must be of type CramerShoupParameterSpec");
			}
			//If we got to this point, it's OK to force params to behave like CramerShoupParameterSpec.
			
			//Set the source of randomness
			this.random = ((CramerShoupParameterSpec) params).getSecureRandom();
			//Then we know for sure that it has a getGroupParams() function that we can use.
			dlogGroup.init(((CramerShoupParameterSpec) params).getDlogGroupParams()); //Dlog shouldn't throw IOException. Once it's removed the compiler won't complain about this.
		}
		
		
		//Now we finished doing all the initialization work, mark this object as initialized:
		isInitialized = true;
	}


	/* (non-Javadoc)
	 * 		If !dlogGroup.convertByteArrayToGroupElement(plaintext.getText()) throw exception.
			Choose a random  r in Zq
			Calculate 	u1 = g1^r
                 		u2 = g2^r
                		e = (h^r)*msgEl
			Convert u1, u2, e to byte[] using the dlogGroup
			Compute alpha  - the result of computing the hash function on the concatenation u1+ u2+ e.
			Calculate v = c^r * d^(r*alpha)
			Create and return an CramerShoupCiphertext object with u1, u2, e and v.

	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#encrypt(edu.biu.scapi.midLayer.plaintext.Plaintext)
	 */
	@Override
	public Ciphertext encrypt(Plaintext plaintext) throws UnInitializedException {
		GroupElement msgElement = dlogGroup.convertByteArrayToGroupElement(((BasicPlaintext)plaintext).getText());
		
		BigInteger qMinusOne = dlogGroup.getOrder().subtract(BigInteger.ONE);
		
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		GroupElement u1 = dlogGroup.exponentiate(publicKey.getGenerator1(), r);
		GroupElement u2 = dlogGroup.exponentiate(publicKey.getGenerator2(), r);
		GroupElement hExpr = dlogGroup.exponentiate(publicKey.getH(), r);
		GroupElement e = dlogGroup.multiplyGroupElements(hExpr, msgElement);
		byte[] u1ToByteArray = dlogGroup.convertGroupElementToByteArray(u1);
		byte[] u2ToByteArray = dlogGroup.convertGroupElementToByteArray(u2);
		byte[] eToByteArray = dlogGroup.convertGroupElementToByteArray(e);
		
		//Concatenate u1, u2 and e into msgToHash
		int lengthOfMsgToHash =  u1ToByteArray.length + u2ToByteArray.length + eToByteArray.length;
		byte[] msgToHash = new byte[lengthOfMsgToHash];
		System.arraycopy(u1ToByteArray, 0, msgToHash, 0, u1ToByteArray.length);
		System.arraycopy(u2ToByteArray, 0, msgToHash, u1ToByteArray.length, u2ToByteArray.length);
		System.arraycopy(eToByteArray, 0, msgToHash, u2ToByteArray.length, eToByteArray.length);
		
		//Calculate the hash of msgToHash
		
		//call the update function in the Hash interface.
		hash.update(msgToHash, 0, msgToHash.length);

		//get the result of hashing the updated input.
		byte[] alpha = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(alpha, 0);
		
		
		//Calculate v = c^r * d^(r*alpha)
		GroupElement cExpr = dlogGroup.exponentiate(publicKey.getC(), r);
		BigInteger q = dlogGroup.getOrder();
		BigInteger rAlphaModQ = (r.multiply(new BigInteger(alpha))).mod(q);
		GroupElement dExpRAlpha = dlogGroup.exponentiate(publicKey.getD(), rAlphaModQ);
		GroupElement v = dlogGroup.multiplyGroupElements(cExpr, dExpRAlpha); 
		
		//Create and return an CramerShoupCiphertext object with u1, u2, e and v.
		CramerShoupCiphertext cipher = new CramerShoupCiphertext(u1, u2, e, v);
		return cipher;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#decrypt(edu.biu.scapi.midLayer.ciphertext.Ciphertext)
	 */
	@Override
	public Plaintext decrypt(Ciphertext ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#generateKey(edu.biu.scapi.midLayer.asymmetricCrypto.keys.AsymKeyGenParameterSpec, java.security.SecureRandom)
	 */
	@Override
	public KeyPair generateKey(AsymKeyGenParameterSpec keyParams, SecureRandom random) throws InvalidParameterSpecException{
		return ScCramerShoupDDH.keyGen(keyParams, random, dlogGroup);
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#generateKey(java.security.SecureRandom)
	 * 	Given a Dlog Group (G, q, g) do: 
			Choose two distinct, random generators g1, g2. (how?)
			Choose five random values (x1, x2, y1, y2, z) in Zq.
			Compute c = g_1^(x_1 ) g_2^(x_2 ), d= g_1^(y_1 ) g_2^(y_2 ), h= g_1^z.
			Set the public key part of the key pair to be c, d, h. (Or (G, q, g, c, d, h) ?)
			Set the private key part of the key pair to be x1, x2, y1, y2, z. (Or (G, q, g, x1, x2, y1, y2, z) ?)
			Return the key pair.

	 */
	@Override
	public KeyPair generateKey(SecureRandom random) {
		return ScCramerShoupDDH.keyGen(null, random, dlogGroup);
	}
	
	public static KeyPair keyGen(AsymKeyGenParameterSpec params, SecureRandom random, DlogGroup dlogGroup) {
		if(!dlogGroup.isInitialized())
			return null;
		GroupElement generator1 = null;
		GroupElement generator2 = null;
		do {
			try {
				//(What source of randomness do we use here?)
				generator1 = dlogGroup.getRandomElement();
				generator2 = dlogGroup.getRandomElement();
			} catch (UnInitializedException e) {
				//Do nothing here. It cannot get here since we already checked at the beginning of this function
				//if the dlog group is initialized.
			}
		}while(generator1.equals(generator2));
		//Check that the "generators" randomly chosen are actually generators and are distinct:
		
		//Choose five random values (x1, x2, y1, y2, z) in Zq.
		BigInteger qMinusOne = null;
		try {
			qMinusOne = dlogGroup.getOrder().subtract(BigInteger.ONE);
		} catch (UnInitializedException e1) {
			e1.printStackTrace();
		}
		BigInteger x1 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger x2 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger y1 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger y2 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger z = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		
		//Calculate c, d and h:
		GroupElement c = null;
		GroupElement d = null; 
		GroupElement h = null;
		
		try {
			c = dlogGroup.multiplyGroupElements(dlogGroup.exponentiate(generator1,x1), dlogGroup.exponentiate(generator2, x2));
			d = dlogGroup.multiplyGroupElements(dlogGroup.exponentiate(generator1,y1), dlogGroup.exponentiate(generator2, y2));
			h = dlogGroup.exponentiate(generator1, z);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (UnInitializedException e) {
			e.printStackTrace();
		}
		CramerShoupPublicKey publicKey = new ScCramerShoupPublicKey(c, d, h, generator1, generator2);
		
		CramerShoupPrivateKey privateKey = new ScCramerShoupPrivateKey(x1, x2, y2, y2, z);
		
		KeyPair keyPair = new KeyPair(publicKey, privateKey);
		
		return keyPair;
	}
	

	/**
	 * In case that the dlog is not initialized and the init function didn't get a GroupParams to initialize it,
	 * this function initialize it with default values.
	 */
	private void initDlogDefault(){
		
		if (dlogGroup instanceof DlogECF2m){
			((DlogECF2m)dlogGroup).init("B-163");
		}
		if (dlogGroup instanceof DlogECFp){
			((DlogECFp)dlogGroup).init("P-192");
		}
		if (dlogGroup instanceof DlogZp){
			((DlogZp)dlogGroup).init(1024);
		}
	}


	@Override
	public boolean isInitialized() {
		// TODO Auto-generated method stub
		return false;
	}


	@Override
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public String getAlgorithmName() {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams)
			throws InvalidParameterSpecException {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams,
			SecureRandom random) throws InvalidParameterSpecException {
		// TODO Auto-generated method stub
		return null;
	}
}

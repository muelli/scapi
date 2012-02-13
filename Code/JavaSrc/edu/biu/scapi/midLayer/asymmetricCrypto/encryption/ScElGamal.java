package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.logging.Level;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPublicKey;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.ciphertext.ElGamalCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.DlogECF2m;
import edu.biu.scapi.primitives.dlog.DlogECFp;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.DlogZp;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.bc.BcDlogECFp;
import edu.biu.scapi.primitives.dlog.groupParams.ZpGroupParams;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * This class performs the El Gamal encryption and decryption scheme.
 * By definition, this encryption scheme is CPA-secure.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ScElGamal implements ElGamalEnc{
	
	private DlogGroup dlog;					//the underlying DlogGroup
	private ScElGamalPrivateKey privateKey;	//ElGamal private key (contains x)
	private ScElGamalPublicKey publicKey;		//ElGamal public key (contains h)
	private AlgorithmParameterSpec params;	//can be padding parameters
	private SecureRandom random;			//source of randomness
	private boolean isInitialized = false;
	
	/**
	 * Default constructor. The default DlogGroup is BcDlogECFp and is initialized with P-192 NIST's curve.
	 */
	public ScElGamal() {
		dlog = new BcDlogECFp();
		((DlogECFp) dlog).init("P-192");
	}
	
	/**
	 * Constructor that gets a DlogGroup and set it to the underlying group
	 * @param dlogGroup must be DDH secure
	 * @throws UnInitializedException if the given dlog group is not initialized
	 */
	public ScElGamal(DlogGroup dlogGroup) throws UnInitializedException{
		//the underlying dlog group must be initialized
		if(!(dlogGroup.isInitialized())){
			throw new UnInitializedException("the given prp argument must be initialized");
		}
		//the underlying dlog group must be DDH secure
		if (!(dlogGroup instanceof DDH)){
			throw new IllegalArgumentException("DlogGroup should have DDH security level");
		}
		dlog = dlogGroup;
	}
	
	/**
	 * Constructor that gets a DlogGroup and set it to the underlying group
	 * @param dlogGroup must be DDH secure
	 * @throws UnInitializedException if the given dlog group is not initialized
	 * @throws FactoriesException if the creation of the dlog failed
	 */
	public ScElGamal(String dlogName) throws FactoriesException{
		//create the DlogGroup
		DlogGroup dlogGroup = DlogGroupFactory.getInstance().getObject(dlogName);
		//the underlying dlog group must be DDH secure
		if (!(dlogGroup instanceof DDH)){
			throw new IllegalArgumentException("DlogGroup should have DDH security level");
		}
		dlog = dlogGroup;
	}
	
	/**
	 * Initialize this ElGamal encryption scheme with keys and AlgorithmParameterSpec.
	 * After this initialization the user can encrypt and decrypt messages.
	 * @param publicKey should be ElGamalPublicKey
	 * @param privateKey should be ElGamalPrivateKey
	 * @param params can be GroupParams to initialize the DlogGroup
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey,
			AlgorithmParameterSpec params) throws IllegalArgumentException, IOException {
		//call the corresponding init function that get a random with the default source of randomness
		init(publicKey, privateKey, params, new SecureRandom());
	}

	/**
	 * Initialize this ElGamal encryption scheme with keys, AlgorithmParameterSpec and source of randomness.
	 * After this initialization the user can encrypt and decrypt messages.
	 * @param publicKey should be ElGamalPublicKey
	 * @param privateKey should be ElGamalPrivateKey
	 * @param params can be GroupParams to initialize the DlogGroup
	 * @param random source of secure randomness
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey,
			AlgorithmParameterSpec params, SecureRandom random) throws IllegalArgumentException, IOException {
		//key should be ElGamal keys
		if(!(publicKey instanceof ScElGamalPublicKey) || !(privateKey instanceof ScElGamalPrivateKey)){
			throw new IllegalArgumentException("keys should be instances of ElGamal keys");
		}
		if (!(params instanceof ElGamalParameterSpec)){
			throw new IllegalArgumentException("params should be instances of ElGamalParameterSpec");
		}
		//set the parameters
		this.publicKey = (ScElGamalPublicKey) publicKey;
		
		//initialize dlog
		this.params = params;
		dlog.init(((ElGamalParameterSpec) params).getGroupParams());
			
		//operates an optimization of the private key
		initPrivateKey(privateKey);
		
		this.random = random;
		//mark this object as initialized
		isInitialized = true;
	}

	/**
	 * Initialize this ElGamal encryption scheme with keys.
	 * After this initialization the user can encrypt and decrypt messages.
	 * @param publicKey should be ElGamalPublicKey
	 * @param privateKey should be ElGamalPrivateKey
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey) {
		//call the corresponding init function that get a random with the default source of randomness
		init(publicKey, privateKey, new SecureRandom());
	}

	/**
	 * Initialize this ElGamal encryption scheme with keys and source of randomness.
	 * After this initialization the user can encrypt and decrypt messages.
	 * @param publicKey should be ElGamalPublicKey
	 * @param privateKey should be ElGamalPrivateKey
	 * @param random source of secure randomness
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey,
			SecureRandom random) {
		//key should be ElGamal keys
		if(!(publicKey instanceof ScElGamalPublicKey) || !(privateKey instanceof ScElGamalPrivateKey)){
			throw new IllegalArgumentException("keys should be instances of ElGamal keys");
		}
		//set the parameters
		this.publicKey = (ScElGamalPublicKey) publicKey;
		
		//initialize dlog
		if (!dlog.isInitialized()){
			initDlogDefault();
		}
		
		//operates an optimization of the private key
		initPrivateKey(privateKey);	
		
		this.random = random;
		//mark this object as initialized
		isInitialized = true;
	}

	/**
	 * Initialize this ElGamal encryption scheme with public key and AlgorithmParameterSpec.
	 * After this initialization the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be ElGamalPublicKey
	 * @param params can be GroupParams to initialize the DlogGroup
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public void init(PublicKey publicKey, AlgorithmParameterSpec params) throws IllegalArgumentException, IOException {
		//call the corresponding init function that get a random with the default source of randomness
		init(publicKey, params, new SecureRandom());
	}

	/**
	 * Initialize this ElGamal encryption scheme with public key, AlgorithmParameterSpec and source of randomness.
	 * After this initialization the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be ElGamalPublicKey
	 * @param params can be GroupParams to initialize the DlogGroup
	 * @param random source of secure randomness
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public void init(PublicKey publicKey, AlgorithmParameterSpec params,
			SecureRandom random) throws IllegalArgumentException, IOException {
		//public key should be ElGamal public key
		if(!(publicKey instanceof ScElGamalPublicKey)){
			throw new IllegalArgumentException("key should be instances of ElGamal key");
		}
		if (!(params instanceof ElGamalParameterSpec)){
			throw new IllegalArgumentException("params should be instances of ElGamalParameterSpec");
		}
		//set the key
		this.publicKey = (ScElGamalPublicKey) publicKey;
		
		//initialize dlog
		this.params = params;
		dlog.init(((ElGamalParameterSpec) params).getGroupParams());
		
		this.random = random;
		//mark this object as initialized
		isInitialized = true;
	}

	/**
	 * Initialize this ElGamal encryption scheme with public key.
	 * After this initialization the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be ElGamalPublicKey
	 */
	public void init(PublicKey publicKey) {
		//call the corresponding init function that get a random with the default source of randomness
		init(publicKey, new SecureRandom());	
	}

	/**
	 * Initialize this ElGamal encryption scheme with public keyand source of randomness.
	 * After this initialization the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be ElGamalPublicKey
	 * @param random source of secure randomness
	 */
	public void init(PublicKey publicKey, SecureRandom random) {
		//public key should be ElGamal public key
		if(!(publicKey instanceof ScElGamalPublicKey)){
			throw new IllegalArgumentException("key should be instances of ElGamal key");
		}
		//set the parameters
		this.publicKey = (ScElGamalPublicKey) publicKey;
		this.random = random;
		
		//initialize dlog
		if (!dlog.isInitialized()){
			initDlogDefault();
		}
		
		//mark this object as initialized
		isInitialized = true;
	}

	/**
	 * ElGamal decrypt function can be optimized if, instead of using the x value in the private key as is, 
	 * we change it to be q-x, while q is the dlog group order.
	 * This function operates this changing and save the new private value as the private key memeber
	 * @param privateKey to change
	 */
	private void initPrivateKey(PrivateKey privateKey){
		//get the a value from the private key
		BigInteger x = ((ScElGamalPrivateKey) privateKey).getX();
		try {
			//get the q-x value
			BigInteger xInv = dlog.getOrder().subtract(x);
			//set the q-x value as the private key
			this.privateKey = new ScElGamalPrivateKey(xInv);
		} catch (UnInitializedException e) {
			// shouldn't occur since dlog group is initialized 
			e.printStackTrace();
		}
	}
	
	/**
	 * In case that the dlog is not initialized and the init function didn't get a GroupParams to initialize it,
	 * this function initialize it with default values.
	 */
	private void initDlogDefault(){
		
		if (dlog instanceof DlogECF2m){
			((DlogECF2m)dlog).init("B-163");
		}
		if (dlog instanceof DlogECFp){
			((DlogECFp)dlog).init("P-192");
		}
		if (dlog instanceof DlogZp){
			BigInteger q = null;
			BigInteger xG = null;
			BigInteger p = null;
			ZpGroupParams params = new ZpGroupParams(q, xG, p);
			try {
				((DlogZp)dlog).init(params);
			} catch (IOException e) {
				// shouldn't occur since that can occur in EC cases
				e.printStackTrace();
			}
		}
	}
	
	@Override
	public boolean isInitialized(){
		return isInitialized;
	}
	
	@Override
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		//if this object is not initialized, throw exception
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		//return the params
		return params;
	}
	
	/**
	 * @return the name of this AsymmetricEnc - ElGamal and the underlying dlog group type
	 */
	public String getAlgorithmName(){
		return "ElGamal/"+dlog.getGroupType();
	}
	
	/**
	 * Encrypts the given message using ElGamal encryption scheme.
	 * Pseudo-code:
	 * 		•	Choose a random  y <- Zq
	 *		•	Calculate c1 = g^y mod p //mod p operation are performed automatically by the group.
	 *		•	Calculate c2 = h^y * plaintext.getText() mod p
	 * @param plaintext contains message to encrypt
	 * @return CipherText of type ElGamalCiphertext contains the encrypted message
	 * @throws UnInitializedException if this object is not initialized
	 */
	public Ciphertext encrypt(Plaintext plaintext) throws UnInitializedException {
		//the object must be initialized in order to encrypt messages
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		//convert the message to a group element. 
		//if the message is not a group element, the function convertByteArrayToGroupElement will throw IllegalArgumentException, which we catch.
		try {
			GroupElement msgElement = dlog.convertByteArrayToGroupElement(((BasicPlaintext)plaintext).getText());
		
			//choose a random value y<-Zq
			BigInteger qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
			BigInteger y = BigIntegers.createRandomInRange(BigInteger.ONE, qMinusOne, random);
			
			//calculate c1 = g^y and c2 = msg * h^y
			GroupElement generator = dlog.getGenerator();
			GroupElement c1 = dlog.exponentiate(generator, y);
			GroupElement hy = dlog.exponentiate(publicKey.getH(), y);
			GroupElement c2 = dlog.multiplyGroupElements(hy, msgElement);
			
			//return an ElGamalCiphertext with c1, c2
			ElGamalCiphertext cipher = new ElGamalCiphertext(c1, c2);
			return cipher;
			
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("the given message is not a valid member in this underlying DlogGroup");
		}
	}

	/**
	 * Decrypts the given ciphertext using ElGamal encryption scheme.
	 * Pseudo-code:
	 * 		•	Calculate s = ciphertext.getC1() ^ privateKey
	 *		•	Calculate the inverse of s: invS =  s ^ -1
	 *		•	Calculate m = ciphertext.getC2() * invS
	 * @param cipherText of type ElGamalCiphertext contains the cipher to decrypt
	 * @return Plaintext contains the decrypted message
	 */
	public Plaintext decrypt(Ciphertext cipher) {
		//if there is no private key, throw exception
		if (privateKey == null){
			throw new IllegalStateException("in order to decrypt a message, this object must be initialized with private key");
		}
		//ciphertext should be ElGamal ciphertext
		if (!(cipher instanceof ElGamalCiphertext)){
			throw new IllegalArgumentException("ciphertext should be instance of ElGamalCiphertext");
		}
		Plaintext plaintext = null;
		try {
			ElGamalCiphertext ciphertext = (ElGamalCiphertext) cipher;
			//calculates s = ciphertext.getC1() ^ x
			GroupElement s = dlog.exponentiate(ciphertext.getC1(), privateKey.getX());
			//calculate the plaintext element m = ciphertext.getC2() * s
			GroupElement m = dlog.multiplyGroupElements(ciphertext.getC2(), s);
			
			//convert the plaintext element to a byte[], create a plaintext object with the bytes and return it
			byte[] text = dlog.convertGroupElementToByteArray(m);
			plaintext = new BasicPlaintext(text);
			
		} catch (UnInitializedException e) {
			// shouldn't occur since the initialization was checked before
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		return plaintext;
	}

	/**
	 * Generates a KeyPair contains set of ElGamalPublicKEy and ElGamalPrivateKey using default source of randomness.
	 * @param keyParams ElGamalParameterSpec.
	 * @return KeyPair contains keys for this El Gamal object
	 * @throws InvalidParameterSpecException 
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		return keyGen(keyParams);
	}

	/**
	 * Generates a KeyPair contains set of ElGamalPublicKEy and ElGamalPrivateKey using the given random.
	 * @param keyParams ElGamalParameterSpec.
	 * @param random source of randomness
	 * @return KeyPair contains keys for this El Gamal object
	 * @throws InvalidParameterSpecException 
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams, SecureRandom random) throws InvalidParameterSpecException {
		return keyGen(keyParams, random);
	}

	/**
	 * Generates a KeyPair contains set of ElGamalPublicKEy and ElGamalPrivateKey using default source of randomness.
	 * @param keyParams ElGamalParameterSpec.
	 * @return KeyPair contains keys for this El Gamal object
	 * @throws InvalidParameterSpecException 
	 */
	public static KeyPair keyGen(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		//call the generateKey function with default source of randomness
		return keyGen(keyParams, new SecureRandom());
	}
	
	public static KeyPair keyGen(AlgorithmParameterSpec keyParams, SecureRandom random) throws InvalidParameterSpecException {
		if (!(keyParams instanceof ElGamalParameterSpec)){
			throw new InvalidParameterSpecException("params should be instance of ElGamalParameterSpec");
		}
		DlogGroup dlog = createDlogGroup((ElGamalParameterSpec) keyParams);
		
		KeyPair pair = null;
		try {
			//choose a random value in Zq
			BigInteger x = BigIntegers.createRandomInRange(BigInteger.ONE, dlog.getOrder(), random);
			GroupElement generator = dlog.getGenerator();
			//calculates h = g^x
			GroupElement h = dlog.exponentiate(generator, x);
			//create an ElGamalPublicKey with h and ElGamalPrivateKey with x
			ScElGamalPublicKey publicKey = new ScElGamalPublicKey(h);
			ScElGamalPrivateKey privateKey = new ScElGamalPrivateKey(x);
			//create a KeyPair with the created keys
			pair = new KeyPair(publicKey, privateKey);
		} catch (UnInitializedException e) {
			// shouldn't occur since dlog group is initialized
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		return pair;
	}
	
	/**
	 * Creates DlogGroup using the ElGamalParameterSpec
	 * @param keyParams ElGamalParameterSpec
	 * @return initialized dlogGroup
	 */
	private static DlogGroup createDlogGroup(ElGamalParameterSpec keyParams) {
		try {
			DlogGroup dlog = null;
			String provider = keyParams.getProviderName();
			if (provider == null){
				dlog = DlogGroupFactory.getInstance().getObject(keyParams.getDlogName());
			} else {
				dlog = DlogGroupFactory.getInstance().getObject(keyParams.getDlogName(), provider);
			}
			dlog.init(keyParams.getGroupParams());
			return dlog;
			
		} catch(Exception e){
			
		}
		return null;
	}
	
	public Ciphertext multiply(Ciphertext cipher1, Ciphertext cipher2) {
		
		return null;
	}

	

}

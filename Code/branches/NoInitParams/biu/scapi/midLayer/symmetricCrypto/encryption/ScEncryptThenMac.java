package edu.biu.scapi.midLayer.symmetricCrypto.encryption;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.ciphertext.EncMacCiphertext;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.midLayer.symmetricCrypto.AuthEncParameterSpec;
import edu.biu.scapi.midLayer.symmetricCrypto.AuthenticationParameterSpec;
import edu.biu.scapi.midLayer.symmetricCrypto.SymEncParameterSpec;
import edu.biu.scapi.midLayer.symmetricCrypto.keys.AuthEncKeyGenParameterSpec;
import edu.biu.scapi.midLayer.symmetricCrypto.keys.EncThenMacKey;
import edu.biu.scapi.midLayer.symmetricCrypto.keys.SymKeyGenParameterSpec;
import edu.biu.scapi.midLayer.symmetricCrypto.mac.Mac;
import edu.biu.scapi.tools.Factories.MacFactory;
import edu.biu.scapi.tools.Factories.SymmetricEncFactory;

/**
 * This class implements a type of authenticated encryption: encrypt then mac.<p>
 * The encryption algorithm first encrypts the message and then calculates a mac on the encrypted message.<p>
 * The decrypt algorithm receives an encrypted message and a tag. It first verifies the encrypted message with the tag. If verifies, then it proceeds to decrypt using the underlying
 * decrypt algorithm, if not returns a null response.<p>
 * This encryption scheme achieves Cca2 and NonMalleable security level.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScEncryptThenMac implements AuthenticatedEnc {
	
	private SymmetricEnc encryptor;		//The symmetric encryption object used to perform the encrypt part of encrypt-then-mac algorithm
	private Mac mac;					//The mac object used to perform the authentication part of encrypt-then-mac algorithm
	
	/**
	 * Constructor that gets an Encryption-Scheme name and a Mac name, creates and sets the underlying respective encryption and mac .
	 * @param encName the name of the symmetric encryption algorithm
	 * @param macName the name of the mac 
	 * @throws FactoriesException if the creation of the underlying encryption or mac failed
	 */
	public ScEncryptThenMac(String encName, String macName) throws FactoriesException {
		//Create and set the underlying encryption
		SymmetricEnc enc = SymmetricEncFactory.getInstance().getObject(encName);
		//We need to make sure that the encryption scheme requested is not an authenticated encryption scheme as well,
		//so that we do not enter a loop.
		if(enc instanceof AuthenticatedEnc) {
			throw new IllegalArgumentException("A symmetric encryption that is not of type AuthenticatedEnc is needed");
		}
		this.encryptor = enc;
		//Create and set the underlying mac
		Mac mac = MacFactory.getInstance().getObject(macName);
		this.mac = mac;
	}
	
	/**
	 * Constructor that gets an initialized SymmetricEncryption object and an initialized Mac object and sets them as the underlying respective members. 
	 * After using this constructor, there is no need to call init.
	 * @param encryptor the SymmetricEncryption that will be used for the encryption part of this scheme
	 * @param mac the Mac that will be used for the authentication part of this scheme
	 * @throws UnInitializedException if the given Encryption or Mac are not initialized
	 */
	public ScEncryptThenMac(SymmetricEnc encryptor, Mac mac) throws UnInitializedException {
		if (!encryptor.isInitialized()) {
			throw new UnInitializedException("The Symmetric Encryption argument must be initialized");
		}
		if (!mac.isInitialized()) {
			throw new UnInitializedException("The Mac argument must be initialized");
		}
		if(encryptor instanceof AuthenticatedEnc)
			throw new IllegalArgumentException("A symmetric encryption that is not of type AuthenticatedEnc is needed");
		this.encryptor = encryptor;
		this.mac = mac;
	}

	/**
	 * Initializes this encryption with a secret key.
	 * @param secretKey secret key has to be of type <link>EncThenMacKey<link>
	 * @throws InvalidKeyException
	 */
	@Override
	public void init(SecretKey secretKey) throws InvalidKeyException {
		if(!(secretKey instanceof EncThenMacKey))
			throw new InvalidKeyException("This encryption requires a key of type EncThenMacKey");
		SecureRandom newRandom = new SecureRandom();
		init(secretKey, newRandom);
	}

	/**
	 * This function initializes the encrypt-then-mac object.
	 * It checks that the given secretKey is of type AuthenticatedKey. If not throws InvalidKeyException.<p>
	 * It then calls encryptor’s relevant init with corresponding key and mac’s relevant init with corresponding key.
	 * 
	 * @throws InvalidKeyException if key is not of type EncThenMacKey
	 */
	@Override
	public void init(SecretKey secretKey, SecureRandom random)
			throws InvalidKeyException {
		if(!(secretKey instanceof EncThenMacKey))
			throw new InvalidKeyException("This encryption requires a key of type EncThenMacKey");
		EncThenMacKey key =  (EncThenMacKey) secretKey;
		encryptor.init(key.getEncryptionKey(), random);
		mac.init(key.getMacKey(), random);
	}

	@Override
	public void init(SecretKey secretKey, AlgorithmParameterSpec params)
			throws InvalidKeyException, InvalidParameterSpecException, FactoriesException {
		//Check for validity of input before creating an instance of SecureRandom, to avoid waste of resources.
		if(!(secretKey instanceof EncThenMacKey))
			throw new InvalidKeyException("This encryption requires a key of type EncThenMacKey");
		if(! (params instanceof AuthEncParameterSpec))
			throw new InvalidParameterSpecException("The parameters have to be of type AuthEncParameterSpec");
		//Get a source of randomness and call the relevant init function.
		SecureRandom newRandom = new SecureRandom();
		init(secretKey, params, newRandom);
	}

	@Override
	public void init(SecretKey secretKey, AlgorithmParameterSpec params,
			SecureRandom random) throws InvalidKeyException,
			InvalidParameterSpecException, FactoriesException {
		//Validate the SecretKey.
		if(!(secretKey instanceof EncThenMacKey))
			throw new InvalidKeyException("This encryption requires a key of type EncThenMacKey");
		//If valid, then cast it to right type.
		EncThenMacKey key =  (EncThenMacKey) secretKey;
		
		//Validate the parameters.
		if(! (params instanceof AuthEncParameterSpec))
				throw new InvalidParameterSpecException("The parameters have to be of type AuthEncParameterSpec");
		//If valid, then cast them to right type.
		AuthEncParameterSpec newParams = (AuthEncParameterSpec) params;
		
		encryptor.init(key.getEncryptionKey(), newParams.getEncParams(), random);
		mac.init(key.getMacKey(), newParams.getMacParams(), random);

	}

	/**
	 * Checks if this object has been initialized.
	 */
	@Override
	public boolean isInitialized() {
		//If both the underlying encryptor and the underlying mac are initialized then return true.
		//Else, return false
		boolean isInitialized = encryptor.isInitialized() && mac.isInitialized();
		return isInitialized;
	}

	@Override
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		AuthEncParameterSpec params = new AuthEncParameterSpec((SymEncParameterSpec)encryptor.getParams(), (AuthenticationParameterSpec)mac.getParams());
		return params;
	}

	@Override
	public String getAlgorithmName() {
		return "EncryptThenMacWith" + encryptor.getAlgorithmName() + "And" + mac.getAlgorithmName();
	}

	/**
	 * This function generates an authenticated key and uses SCAPI’s default source of randomness. The given keySize is in bits.
	 */
	@Override
	public SecretKey generateKey(AlgorithmParameterSpec keySize)
			throws InvalidParameterSpecException {
		if(!(keySize instanceof AuthEncKeyGenParameterSpec))
			throw new InvalidParameterSpecException("keySize has to be of type AuthEncKeyGenParameterSpec");
		return generateKey(keySize, new SecureRandom());
	}

	@Override
	public SecretKey generateKey(AlgorithmParameterSpec keySize,
			SecureRandom random) throws InvalidParameterSpecException {
		if(!(keySize instanceof AuthEncKeyGenParameterSpec))
			throw new InvalidParameterSpecException("keySize has to be of type AuthEncKeyGenParameterSpec");
		AuthEncKeyGenParameterSpec params = (AuthEncKeyGenParameterSpec) keySize;
		SecretKey encKey = encryptor.generateKey(new SymKeyGenParameterSpec(params.getEncKeySize()), random);
		SecretKey macKey = mac.generateKey(new SymKeyGenParameterSpec(params.getMacKeySize()), random);
		EncThenMacKey key = new EncThenMacKey(encKey, macKey);
		return key;
	}

	@Override
	public SymmetricCiphertext encrypt(Plaintext plaintext)
			throws UnInitializedException {
		if(!isInitialized())
			throw new UnInitializedException();

		BasicPlaintext text = (BasicPlaintext) plaintext;
		int length = text.getText().length;
		
		SymmetricCiphertext basicCipher = encryptor.encrypt(plaintext);
		byte[] tag = mac.mac(basicCipher.getBytes(), 0, length);
		EncMacCiphertext encMacCipher = new EncMacCiphertext(basicCipher, tag); 
		return (SymmetricCiphertext) encMacCipher;
	}

	@Override
	public SymmetricCiphertext encrypt(Plaintext plaintext, byte[] iv)
			throws UnInitializedException, IllegalBlockSizeException {
		if(!isInitialized())
			throw new UnInitializedException();

		BasicPlaintext text = (BasicPlaintext) plaintext;
		int length = text.getText().length;
		
		SymmetricCiphertext basicCipher = encryptor.encrypt(plaintext, iv);
		byte[] tag = mac.mac(basicCipher.getBytes(), 0, length);
		EncMacCiphertext encMacCipher = new EncMacCiphertext(basicCipher, tag); 
		return (SymmetricCiphertext) encMacCipher;
	}

	@Override
	public Plaintext decrypt(Ciphertext ciphertext)
			throws UnInitializedException {
		if(!isInitialized())
			throw new UnInitializedException();
			
		if(! (ciphertext instanceof EncMacCiphertext) )
			throw new IllegalArgumentException("The ciphertext to decrypt has to be of type EncMacCiphertext");
		EncMacCiphertext encMacCipher = (EncMacCiphertext) ciphertext;
		boolean isVerified = mac.verify(encMacCipher.getBytes(), 0, encMacCipher.getLength(), encMacCipher.getTag());
		
		if(!isVerified){
			return null;
		}
		
		//Now that the message has been verified we can decrypt it:
		return encryptor.decrypt(encMacCipher.getCipher());
	}

}

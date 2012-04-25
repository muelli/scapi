/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Vector;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDamgardJurikPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.ciphertext.CramerShoupCiphertext;
import edu.biu.scapi.midLayer.ciphertext.DJCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.trapdoorPermutation.RSAModulus;
import edu.biu.scapi.primitives.trapdoorPermutation.ScRSAPermutation;
import edu.biu.scapi.tools.math.MathAlgorithms;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScDamgardJurikEnc implements DamgardJurikEnc {
	
	private DamgardJurikPublicKey publicKey;
	private DamgardJurikPrivateKey privateKey;
	private SecureRandom random;
	private BigInteger qMinusOne; 
	private boolean isKeySet = false;


	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#setKey(java.security.PublicKey, java.security.PrivateKey)
	 */
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey)	throws InvalidKeyException {
		//public key should be Cramer Shoup public key
		if(!(publicKey instanceof ScDamgardJurikPublicKey)){
			throw new InvalidKeyException("The public key must be of type DamgardJurikPublicKey");
		}
		//Set the public key
		this.publicKey = (ScDamgardJurikPublicKey) publicKey;

		//private key should be Cramer Shoup private key	
		if(privateKey == null){
			//If the private key in the argument is null then this instance's private key should be null.  
			this.privateKey = null;
		}else{
			if(!(privateKey instanceof ScDamgardJurikPrivateKey)){
				throw new InvalidKeyException("The private key must be of type DamgardJurikPrivateKey");
			}
			//Set the private key
			this.privateKey = (ScDamgardJurikPrivateKey) privateKey;
		}
		isKeySet = true;

	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#setKey(java.security.PublicKey)
	 */
	@Override
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		setKey(publicKey, null);

	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#isKeySet()
	 */
	@Override
	public boolean isKeySet() {
		// TODO Auto-generated method stub
		return isKeySet;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#getAlgorithmName()
	 */
	@Override
	public String getAlgorithmName() {
		
		return "DamgardJurik";
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#encrypt(edu.biu.scapi.midLayer.plaintext.Plaintext)
	 */
	@Override
	public Ciphertext encrypt(Plaintext plainText) {
		BigInteger x; 
		if(plainText instanceof BasicPlaintext){
			x = new BigInteger(((BasicPlaintext) plainText).getText());
		}
		else if(plainText instanceof BigIntegerPlainText){
			x = ((BigIntegerPlainText)plainText).getX();
		}else{
			throw new IllegalArgumentException("The plaintext has to be either of type BasicPlaintext or of type BigIntegerPlainText");
		}
		int s = (x.bitLength()/publicKey.getModulus().bitLength()) + 1;
		BigInteger N = publicKey.getModulus().pow(s);
		//Make sure the x belongs to ZN
		if(x.compareTo(BigInteger.ZERO) < 0 || x.compareTo(N) >= 0)
			throw new IllegalArgumentException("Message too big for encryption");
		
		BigInteger Ntag = publicKey.getModulus().pow(s+1);
		BigInteger NtagMinus1 = Ntag.subtract(BigInteger.ONE);

		//Choose a random r in ZNtag*, this can be done by choosing a random value between 1 and Ntag -1 
		//which is with overwhelming probability in Zntag*
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ONE, NtagMinus1, random);
		//Compute c = ((1 + n) ^x) * r ^N mod N'
		BigInteger  mult1= (publicKey.getModulus().add(BigInteger.ONE)).modPow(x, Ntag);
		BigInteger mult2 = r.modPow(N, Ntag);
		BigInteger c = (mult1.multiply(mult2)).mod(Ntag);
		return new DJCiphertext(c);
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#decrypt(edu.biu.scapi.midLayer.ciphertext.Ciphertext)
	 */
	@Override
	public Plaintext decrypt(Ciphertext cipher) throws KeyException {
		//if there is no private key, throw exception
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//ciphertext should be Damgard-Jurik ciphertext
		if (!(cipher instanceof DJCiphertext)){
			throw new IllegalArgumentException("cipher should be instance of DJCiphertext");
		}
		
		//Plaintext plaintext = null;

		DJCiphertext djCipher = (DJCiphertext) cipher;
		//n is the modulus in the public key.
		//Calculate s = (|cipher| -1) / |n|
		int s = ((djCipher).getCipher().bitLength() - 1) / publicKey.getModulus().bitLength();

		//Calculate N and N' based on s: N = n^s, N' = n^(s+1)
		BigInteger N = publicKey.getModulus().pow(s);
		BigInteger Ntag = publicKey.getModulus().pow(s+1);
		
		//Make sure the cipher belongs to ZN'
		if(djCipher.getCipher().compareTo(BigInteger.ZERO) < 0 || djCipher.getCipher().compareTo(Ntag) >= 0)
			throw new IllegalArgumentException("The cipher is not in ZN'");
		
		BigInteger d;
		//Optimization for the calculation of d:
		//If s == 1 used the pre-computed d which we have in the private key
		//else, compute d using the Chinese Remainder Theorem, such that d = 1 mod N, and d = 0 mod t.
		if(s==1){
			d = privateKey.getDForS1();
		}else{
			d = generateD(N, privateKey.getT());
		}
		
		//Compute (cipher ^ d) mod N'
		BigInteger cipherToD = djCipher.getCipher().modPow(d, Ntag);  
	
		//Compute x as the discrete logarithm of c^d to the base (1+n)modulo N'
		//This is done by the following computation
		//	a=c^d
		//	x=0
		//	for j = 1 to s do
		//	begin
		//	   t1= ((a mod n^(j+1) ) -  1) / n
		//	   t2 = x
		//	   for k = 2 to j do
		//	   begin
		//	      x = x – 1
		//	      t2 = t2 * x mod nj
		//	      t1 =  (t1 – (t2 * nk-1) / factorial(k) )  mod nj
		//	  end
		//	  x = t1
		//	end
		//	OUTPUT x
		
		
		
		return null;
	}

	private BigInteger generateD(BigInteger N, BigInteger t){
		Vector<BigInteger> congruences = new Vector<BigInteger>();
		congruences.add(BigInteger.ONE);
		congruences.add(BigInteger.ZERO);
		Vector<BigInteger> moduli = new Vector<BigInteger>();
		moduli.add(N);
		moduli.add(privateKey.getT());
		BigInteger d = MathAlgorithms.chineseRemainderTheorem(congruences, moduli);
		return d;
	}
	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#generateKey(java.security.spec.AlgorithmParameterSpec)
	 */
	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams)throws InvalidParameterSpecException {
		if(!(keyParams instanceof DJKeyGenParameterSpec)){
			throw new InvalidParameterSpecException("keyParamas has to be an instance of DJKeyGenParameterSpec");
		}
		int certainty = 40;
		DJKeyGenParameterSpec params = (DJKeyGenParameterSpec)keyParams;
		RSAModulus rsaMod = ScRSAPermutation.generateRSAModulus(params.getModulusLength(), params.getCertainty(), random);
		
		BigInteger pMinus1 = rsaMod.p.subtract(BigInteger.ONE);
		BigInteger qMinus1 = rsaMod.q.subtract(BigInteger.ONE);
		BigInteger gcdPMinus1QMinus1 = pMinus1.gcd(qMinus1);
		BigInteger t = (pMinus1.multiply(qMinus1)).divide(gcdPMinus1QMinus1);
		BigInteger dForS1 = generateD(rsaMod.n, t); //precalculate d for the case that s == 1
		
		return new KeyPair(new ScDamgardJurikPublicKey(rsaMod.n), new ScDamgardJurikPrivateKey(t, dForS1));
		
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#generateKey()
	 */
	@Override
	public KeyPair generateKey() {
		throw new UnsupportedOperationException("Use generateKey function with DJKeyGenParameterSpec");
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.DamgardJurikPaillierEnc#reRandomize(edu.biu.scapi.midLayer.ciphertext.Ciphertext)
	 */
	@Override
	public Ciphertext reRandomize(Ciphertext cipher) {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymAdditiveHomomorphicEnc#add(edu.biu.scapi.midLayer.ciphertext.Ciphertext, edu.biu.scapi.midLayer.ciphertext.Ciphertext)
	 */
	@Override
	public Ciphertext add(Ciphertext cipher1, Ciphertext cipher2) {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymAdditiveHomomorphicEnc#multByConst(edu.biu.scapi.midLayer.ciphertext.Ciphertext, java.math.BigInteger)
	 */
	@Override
	public Ciphertext multByConst(Ciphertext cipher1, BigInteger constNumber) {
		// TODO Auto-generated method stub
		return null;
	}
}

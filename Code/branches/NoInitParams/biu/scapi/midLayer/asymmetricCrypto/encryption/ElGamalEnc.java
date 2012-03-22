package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import edu.biu.scapi.securityLevel.Cpa;

/**
 * General interface for El Gamal encryption scheme. Every concrete implementation of ElGamal should implement this interface.
 * By definition, this encryption scheme is CPA-secure.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface ElGamalEnc extends AsymMultiplicativeHomomorphicEnc, Cpa{

}

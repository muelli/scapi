package edu.biu.scapi.primitives.prf;

/** 
 * Marker interface. Every class that implements it is signed as Hmac.
 * Hmac has varying input length and thus implements the interface PrfVaryingInputLength.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface Hmac extends PrfVaryingInputLength {
}
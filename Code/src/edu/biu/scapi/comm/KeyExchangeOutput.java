/**
 * Project: scapi.
 * Package: edu.biu.scapi.comm.
 * File: KeyExchangeOutput.java.
 * Creation date Feb 15, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.comm;

import java.security.Key;

/**
 * @author LabTest
 *
 */
public class KeyExchangeOutput implements ProtocolOutput {

	private Key encKey;
	private Key macKey;
	/**
	 * @param encKey the encKey to set
	 */
	public void setEncKey(Key encKey) {
		this.encKey = encKey;
	}
	/**
	 * @return the encKey
	 */
	public Key getEncKey() {
		return encKey;
	}
	/**
	 * @param macKey the macKey to set
	 */
	public void setMacKey(Key macKey) {
		this.macKey = macKey;
	}
	/**
	 * @return the macKey
	 */
	public Key getMacKey() {
		return macKey;
	}
	
	
}

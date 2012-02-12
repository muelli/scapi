/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto;

import java.security.spec.AlgorithmParameterSpec;

import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

/**
 * This class holds parameters needed to initialize an instance of the Cramer-Shoup encryption algorithm.<p>
 * Since Cramer-Shoup is based on a Dlog Group and on a Cryptographic Hash, parameters needed to initialize those underlying parameters are an essential part of this class.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CramerShoupParameterSpec implements AlgorithmParameterSpec {
	//Parameters to initialize the Dlog Group used by Cramer-Shoup
	GroupParams groupParams;

	public CramerShoupParameterSpec(GroupParams groupParams) {
		this.groupParams = groupParams;
	}
	
	public GroupParams getGroupParams(){
		return groupParams;
	}
}

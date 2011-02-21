package edu.biu.scapi.comm;

import java.io.Serializable;

/**
 * 
 */

/** 
 * @author LabTest
 */
public class Message implements Serializable{
	/** 
	 * 
	 */
	private byte[] data = null;

	/** 
	 * @param data
	 */
	public void setData(byte[] data) {
		this.data = data;
	}

	/** 
	 * @return
	 */
	public byte[] getData() {
		return data;
	}
}
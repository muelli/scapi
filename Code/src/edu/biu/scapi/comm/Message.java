package edu.biu.scapi.comm;

/**
 * 
 */

/** 
 * @author LabTest
 */
public abstract class Message {
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
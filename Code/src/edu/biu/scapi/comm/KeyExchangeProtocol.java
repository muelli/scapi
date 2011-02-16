/**
 * Key Exchange Protocols are implemented using the Strategy design pattern so that different protocols can be chosen by the application. 
 * An instance of the chosen concrete class is passed to the CommunicationSetup. We will currently implement three options:
 *   •	Init key, in this protocol each party has already received as input the shared keys.
 *   •	Plain Diffie-Hellman Key Exchange.
 *   •	Universally Composable Diffie-Hellman.
 * Since Key Exchange Protocols are a type of Protocol, they also implement the Protocol Interface. 
 */
package edu.biu.scapi.comm;


/** 
* @author LabTest
 */
public class KeyExchangeProtocol implements Protocol{

	/* (non-Javadoc)
	 * @see edu.biu.scapi.comm.Protocol#getOutput()
	 */
	@Override
	public ProtocolOutput getOutput() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.comm.Protocol#run()
	 */
	@Override
	public void run() {
		// TODO Auto-generated method stub
		
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.comm.Protocol#start(edu.biu.scapi.comm.ProtocolInput)
	 */
	@Override
	public void start(ProtocolInput protocolInput) {
		// TODO Auto-generated method stub
		
	}
}
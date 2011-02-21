/**
 * A SecuringConnectionThread is created by the CommunicationSetup for each party in the input list. 
 * Its job is to establish a physical connection if it is initialized to do so, as well as securing the connection by performing a key 
 * exchange if needed. 
 * For the sake of simplicity, we unify both roles and call this thread SecuringConnectionThread. 
 * The SecuringConnectionThread is needed only for connecting and securing the connection. 
 * Once the securing stage is finished, the thread reaches the end of the run() function, returns from it and dies. 
 * In order for two parties to be able to connect to each other, one needs to be listening for connections and the other needs to connect to it. 
 * In our case it is not relevant which party connects to which, since all parties are equal (this is not a server-client setup). 
 * We devised a simple algorithm to decide the order of the connections:
 * 	• Each party connects to other parties with higher ID number and *
 *  • Listens to parties with lower ID number than its own. *
 * The comparison will be performed based on the string representation of the InetSocketAddress object obtained from the IP and port of the party.
 * If a party needs to listen for connections, we call it a DOWN connection. 
 * If it needs to connect to a higher up party, we call it an UP connection. 
 * The thread will engage in a loop to try to connect. The loop will end either if the connection succeeds or if it is stopped by the object that created the thread, that is, the CommunicationSetup.
 */
package edu.biu.scapi.comm;

import java.io.IOException;
import java.net.InetAddress;
import edu.biu.scapi.comm.Channel;

/** 
 * @author LabTest
 */
public class SecuringConnectionThread extends Thread{
	private PlainChannel channel;
	private boolean bStopped = false;
	private boolean doConnect;
	private InetAddress ipAddres;
	private int port;
	KeyExchangeProtocol keyExchangeProtocol;
	KeyExchangeOutput keyExchangeOutput;
	
	/** 
	 * @param channel
	 * @param IP
	 * @param port
	 * @param doConnect
	 */
	SecuringConnectionThread(PlainChannel channel, InetAddress IP, int port,
			boolean doConnect, KeyExchangeProtocol keyExchangeProtocol, KeyExchangeOutput keyExchangeOutput) {
		
		this.doConnect = doConnect;
		this.channel = channel;
		this.ipAddres = IP;
		this.port = port;
		this.keyExchangeProtocol = keyExchangeProtocol;
		this.keyExchangeOutput = keyExchangeOutput;
		
	}
	
	/**
	 * 
	 * stopConnecting - sets the flag bStopped to false. In the run function of this thread this flag is checked
	 * 					if the flag is true the run functions returns, otherwise continues.
	 */
	void stopConnecting(){
		
		//set the flag to true.
		bStopped = true;
	}
	

	/**
	 * The main function of the thread.
	 */
	public void run() {

		//while thread has not been stopped by owner and connection has failed
		while(!bStopped ){
					
			while(!channel.isConnected()){
				if(doConnect){
					channel.setState(edu.biu.scapi.comm.State.CONNECTING);
					try {
						channel.connect();
					} catch (IOException e) {
	
						//the connection has failed sleep for a little while and try again
						try {
							Thread.sleep(1000);
						} catch (InterruptedException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
						
					}
				}
			}
			
			//set channel state to securing
			channel.setState(edu.biu.scapi.comm.State.SECURING);
			
			//start key exchange protocol
			keyExchangeProtocol.start(null);
			
			//set the output of the protocol with the keys
			KeyExchangeOutput localKeyExchangeOutput = (KeyExchangeOutput) keyExchangeProtocol.getOutput();
			
			//copy the key exchange output to the output that was passed to the object in the constructor
			keyExchangeOutput.setEncKey(localKeyExchangeOutput.getEncKey());
			keyExchangeOutput.setMacKey(localKeyExchangeOutput.getMacKey());
			
			//set the channel state to READY
			channel.setState(edu.biu.scapi.comm.State.READY);
			
		}
		System.out.println("End of securing thread run\n");
	}


	/**
	 * @return the channel
	 */
	Channel getChannel() {
		return channel;
	}
}
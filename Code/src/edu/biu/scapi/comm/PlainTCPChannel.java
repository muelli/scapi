/**
 * 
 */
package edu.biu.scapi.comm;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

/** 
 * @author LabTest
 */
public class PlainTCPChannel extends PlainChannel{
	private Socket socket;
	private ObjectOutputStream outStream;
	private ObjectInputStream inStream;
	private InetSocketAddress address;

	/** 
	 * @param msg
	 * @throws IOException 
	 */
	public void send(Message msg) throws IOException {
		
		outStream.writeObject(msg);
	}

	/** 
	 * @param msg
	 * @throws ClassNotFoundException 
	 * @throws IOException 
	 */
	public Message receive() throws ClassNotFoundException, IOException {
		
		return ((Message)inStream.readObject());
	}

	/**
	 * 
	 * close
	 */
	public void close() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * @param ipAddress
	 * @param port
	 */
	PlainTCPChannel(InetAddress ipAddress, int port) {
		
		address = new InetSocketAddress(ipAddress, port);
	}
	
	/**
	 * 
	 */
	public PlainTCPChannel(InetSocketAddress address) {

		this.address = address;
	}

	/** 
	 * @param existingChannel
	 */
	PlainTCPChannel(Channel existingChannel) {
		// begin-user-code
		// TODO Auto-generated constructor stub
		// end-user-code
	}

	/** 
	 * @param ipAddress
	 * @param port
	 * @param typeOfConnection
	 */
	PlainTCPChannel(InetAddress ipAddress, int port, Object typeOfConnection) {
		
	}

	/** 
	 * Connect : connects the socket to the InetSocketAddress of this object. If the server we are trying to connect to 
	 * 			 is not up yet than we sleep for a while and try again until the connection is established.
	 * 			 After the connection has succeeded the input and output streams are set for the send and receive functions.
	 * @return
	 * @throws IOException 
	 */
	public boolean connect() throws IOException {
		
		//as long as the connect fails try again
		
			
		socket.connect(address);
			
		
		if(socket.isConnected()){
			try {
				outStream = new ObjectOutputStream(socket.getOutputStream());
				inStream = new ObjectInputStream(socket.getInputStream());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		return true;
		
	}

	


	/**
	 * setSocket : Sets the socket and the input and output streams. If the user uses this function it means that 
	 * 			   the connect function will not be called and thus, the streams should be set here.
	 * @param socket the socket to set
	 * 		
	 */
	public void setSocket(Socket socket) {
		this.socket = socket;
		
		try {
			outStream = new ObjectOutputStream(socket.getOutputStream());
			inStream = new ObjectInputStream(socket.getInputStream());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	
}
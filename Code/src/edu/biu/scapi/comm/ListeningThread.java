/**
 * 
 */
package edu.biu.scapi.comm;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Iterator;
import java.util.Map;

/** 
 * @author LabTest
 */
public class ListeningThread extends Thread{
	private Map<InetAddress , SecuringConnectionThread> connectingThreads;//map that includes only SecuringConnectionThread of the down connections
	private int port;//the port to listen on
	private boolean bStopped = false;//a flag that indicates if to keep on listening or stop
	private ServerSocket listener;
	

	/**
	 * 
	 */
	public ListeningThread( Map<InetAddress ,SecuringConnectionThread> securingThreads, int port) {

		connectingThreads = securingThreads;
		this.port = port;
		
		//creta the server socket for future use
		try {
			listener = new ServerSocket(port);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}
	
	/**
	 * 
	 * stopConnecting - sets the flag bStopped to false. In the run function of this thread this flag is checked
	 * 					if the flag is true the run functions returns, otherwise continues.
	 */
	public void stopConnecting(){
		
		//set the flag to true.
		bStopped = true;
	}
	
	
	
	/**
	 * run : This function is the main function of the ListeningThread. Mainly, we listen and accept valid connections as long
	 *  	 as the flag bStopped is false.
	 */
	public void run() {

		//first set the channels in the map to connecting
		Iterator iterator = connectingThreads.keySet().iterator();
		
		while(iterator.hasNext()){  
			Channel ch = ((SecuringConnectionThread)iterator.next()).getChannel();
			
			if(ch instanceof PlainChannel)
		       ((PlainChannel)ch).setState(edu.biu.scapi.comm.State.CONNECTING);
		       
		}
		
		int numOfIncomingConnections = connectingThreads.size();
			
		//loop for incoming connections and make sure that this thread should not stopped.
        for (int i = 0; i < numOfIncomingConnections && bStopped; i++) {
        	
            Socket socket = null;
			try {
				
				//use the server socket to listen on incoming connections.
				// accept connections from all the smaller processes 
				socket = listener.accept();
				
				//s.setTcpNoDelay(true);//consider the 2 options of nagle
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			//get the address from the socket and find it the map
			SecuringConnectionThread scThread = connectingThreads.get(socket.getLocalAddress());
			
			//check if the ip address is a valid address. i.e. exists in the map
			if(scThread==null){//an un authorized ip tried to connect
				i--; //return the index. 
				break;
			}
        	else{ //we have a thread that corresponds to this ip address. Thus, this address is valid
        		
        		//check that the channel is concrete channel and not some decoration
        		if(scThread.getChannel() instanceof PlainTCPChannel){
        			//get the channel from the thread and set the obtained socket.
        			((PlainTCPChannel)scThread.getChannel()).setSocket(socket);
        			
        			//start the connecting thread
        			scThread.start();
        		}
        		else
        			;//throw an exception. The channel must be concrete
        		
        	}
        		
        }
			
		
		
	}
}
// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

import javax.net.ssl.*;

final class TLSClient extends Client {

	SSLEngine engine;
	public TLSClient(long endTime) throws IOException {
		super(SocketChannel.open(), endTime);
	}

	void bind(SocketAddress addr) throws IOException {
		SocketChannel channel = (SocketChannel) key.channel();
		channel.socket().bind(addr);
	}

	void connect(SocketAddress addr) throws IOException {
		try {
			SocketChannel channel = (SocketChannel) key.channel();
			if (channel.connect(addr))
				return;
			key.interestOps(SelectionKey.OP_CONNECT);
			try {
				while (!channel.finishConnect()) {
					if (!key.isConnectable())
						blockUntil(key, endTime);
				}
			} finally {
				if (key.isValid())
					key.interestOps(0);
			}
			
			// start SSL context creation
			SSLContext sslContext = SSLContext.getDefault();
			// We're ready for the engine.
			InetSocketAddress isa = (InetSocketAddress)addr;
			System.out.println("Inet Address " + isa.getAddress().getHostAddress() + " PRT: " +  isa.getPort());
			SSLEngine engine = sslContext.createSSLEngine(isa.getAddress().getHostAddress(), isa.getPort());
			
			// Use as client
			engine.setUseClientMode(true);
			this.engine = engine;
			
			doHandShake(channel);
			
		}catch(Exception ex) {
			ex.printStackTrace();
		}
		
		
	}

	void send(byte[] data) throws IOException {
		SocketChannel channel = (SocketChannel) key.channel();
		verboseLog("TCP write", channel.socket().getLocalSocketAddress(),
				channel.socket().getRemoteSocketAddress(), data);
		byte[] lengthArray = new byte[2];
		lengthArray[0] = (byte) (data.length >>> 8);
		lengthArray[1] = (byte) (data.length & 0xFF);
		ByteBuffer[] buffers = new ByteBuffer[2];
		buffers[0] = ByteBuffer.wrap(lengthArray);
		buffers[1] = ByteBuffer.wrap(data);
		int nsent = 0;
		key.interestOps(SelectionKey.OP_WRITE);
		SSLSession session = engine.getSession();
		ByteBuffer myNetData = ByteBuffer.allocate(session.getPacketBufferSize());
		
		try {
			
			SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
			System.out.println("Handshke Status Sent" +  hs);
			
			// Create byte buffers to use for holding application and encoded data
			 // Generate SSL/TLS encoded data (handshake or application data)
		     
		    	while (buffers[1].hasRemaining()) {	
		    		SSLEngineResult res = engine.wrap(buffers, myNetData);
				    // Process status of call
				    if (res.getStatus() == SSLEngineResult.Status.OK) {
				    		//buffers[1].compact();
					    while (myNetData.hasRemaining()) {
							if (key.isWritable()) {
									long n = channel.write(myNetData);
									if (n < 0)
										throw new EOFException();
									nsent += (int) n;
							} else {
								blockUntil(key, endTime);
						    }// ELSE
					    }// end While
						if (nsent < data.length + 2
									&& System.currentTimeMillis() > endTime) {
								throw new SocketTimeoutException();
						}
						System.out.println("Bytes Sent" +  nsent);
				    }// end If
			} //WHILE
	
		} finally {
			if (key.isValid())
				key.interestOps(0);
		}
		//printSessionInfo ( session, "SEND");
	}
	
	
	private byte[] _recv(int length) throws IOException {
		
		SSLSession session = engine.getSession();
		SocketChannel channel = (SocketChannel) key.channel();
		printSessionInfo ( session,  "Receive");
		int nrecvd = 0;
		byte[] data = new byte[length];
		ByteBuffer peerAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
		ByteBuffer peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
		peerAppData = ByteBuffer.wrap(data);
		
		try {
			SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
			System.out.println("Handshake Status Received" +  hs);
			System.out.println("Data to be processd" +  length);
			key.interestOps(SelectionKey.OP_READ);
			
			while (nrecvd < length) {
					if (key.isReadable()) {
						long n = channel.read(peerNetData);
						System.out.println("Bytes read: " +  n);
						 // Process incoming data
					    SSLEngineResult res = engine.unwrap(peerNetData, peerAppData);
					    if (res.getStatus() == SSLEngineResult.Status.OK) {
					        peerNetData.compact();
					        peerNetData.flip();    
							if (n < 0)
								throw new EOFException();
							nrecvd += (int) n;
							if (nrecvd < length && System.currentTimeMillis() > endTime) {
								throw new SocketTimeoutException();
							}							
							System.out.println("Bytes Received" +  nrecvd);
					    	} 
					} else {
						blockUntil(key, endTime);
				    }
			} // While
		} finally {
			if (key.isValid())
				key.interestOps(0);
		}
		return data;
	}

	byte[] recv() throws IOException {
		byte[] buf = _recv(2);
		int length = ((buf[0] & 0xFF) << 8) + (buf[1] & 0xFF);
		byte[] data = _recv(length);
		SocketChannel channel = (SocketChannel) key.channel();
		verboseLog("TCP read", channel.socket().getLocalSocketAddress(),
				channel.socket().getRemoteSocketAddress(), data);
		return data;
	}

	static byte[] sendrecv(SocketAddress local, SocketAddress remote,
			byte[] data, long endTime) throws IOException {
		TLSClient client = new TLSClient(endTime);
		try {
			if (local != null)
				client.bind(local);
			client.connect(remote);
			client.send(data);
			return client.recv();
		} finally {
			System.out.println("Cleanup");
			client.cleanup();
		}
	}

	static byte[] sendrecv(SocketAddress addr, byte[] data, long endTime)
			throws IOException {
		return sendrecv(null, addr, data, endTime);
	}
	
	static void printSessionInfo (SSLSession session, String location) {
		try {
		System.out.println(location);
		Certificate[] cchain = session.getPeerCertificates();
		for (int i = 0; i < cchain.length; i++) {
		      System.out.println(((X509Certificate) cchain[i]).getSubjectDN());
		    }
		    System.out.println("Peer host is " + session.getPeerHost());
		    System.out.println("Cipher is " + session.getCipherSuite());
		    System.out.println("Protocol is " + session.getProtocol());
		    System.out.println("ID is " + new BigInteger(session.getId()));
		    System.out.println("Session created in " + session.getCreationTime());
		    System.out.println("Session accessed in " + session.getLastAccessedTime());
		}catch(Exception ex) {
			ex.printStackTrace();
			}
	}
	
	private void doHandShake(SocketChannel channel) {
		try {
			 // Create byte buffers to use for holding application data
			SSLSession session = engine.getSession();
			//printSessionInfo (session, "Pre handshake");
		    int appBufferSize = engine.getSession().getApplicationBufferSize();
		   
			ByteBuffer myAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
		    ByteBuffer myNetData = ByteBuffer.allocate(session.getPacketBufferSize());
		    ByteBuffer peerAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
		    ByteBuffer peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
		    
			// Now do the handshake
			this.engine.beginHandshake();
			
			SSLEngineResult.HandshakeStatus hs = this.engine.getHandshakeStatus();
			
			System.out.println("Handshake Status" +  hs);
			while (hs != SSLEngineResult.HandshakeStatus.FINISHED &&
		            hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
				
				hs = this.engine.getHandshakeStatus();
				
				if (hs ==  SSLEngineResult.HandshakeStatus.NEED_WRAP){
					//System.out.println("HS contunued 1" +  hs);
			    		// Empty the local network packet buffer.
		            myNetData.clear();
	
		            // Generate handshaking data
		            SSLEngineResult res = engine.wrap(myAppData, myNetData);
		            hs = res.getHandshakeStatus();
	
		            // Check status
		            if  (res.getStatus() == SSLEngineResult.Status.OK) {
		                myNetData.flip();
	
		                // Send the handshaking data to peer
		                while (myNetData.hasRemaining()) {
		                    if (channel.write(myNetData) < 0) {
		                        // Handle closed channel
		                    }
		                }
		            }		            
				} else if (hs ==  SSLEngineResult.HandshakeStatus.NEED_UNWRAP){
					//System.out.println("HS contunued 2" +  hs);
					// Receive handshaking data from peer
		            if (channel.read(peerNetData) < 0) {
		                // Handle closed channel
		            }
		            // Process incoming handshaking data
		            peerNetData.flip();
		            SSLEngineResult res = engine.unwrap(peerNetData, peerAppData);
		            peerNetData.compact();
		            hs = res.getHandshakeStatus();
		       
				} else if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
					//System.out.println("HS contunued 3" +  hs);
				    Runnable task;
				    while ((task=engine.getDelegatedTask()) != null) {
				        new Thread(task).start();
				    }
				}
		    }
			System.out.println("Whats the final status " +  hs);
			//printSessionInfo (session, "Post handshake");
		}catch(Exception ex) {
			ex.printStackTrace();
		}
	}

		
		

}

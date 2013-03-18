/**
 * CS255 project 2
 */

package mitm;

import java.net.*;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.regex.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;


class MITMAdminServer implements Runnable
{
    private ServerSocket m_serverSocket;
    private Socket m_socket = null;
    private HTTPSProxyEngine m_engine;
    
    public MITMAdminServer( String localHost, int adminPort, HTTPSProxyEngine engine ) throws IOException,GeneralSecurityException {
		MITMSSLSocketFactory socketFactory = new MITMSSLSocketFactory();
				
		m_serverSocket = socketFactory.createServerSocket( localHost, adminPort, 0 );
		m_engine = engine;
    }

    public void run() {
	System.out.println("Admin server initialized, listening on port " + m_serverSocket.getLocalPort());
	while( true ) {
	    try {
		m_socket = m_serverSocket.accept();

		byte[] buffer = new byte[40960];

		Pattern userPwdPattern =
		    Pattern.compile("password:(\\S+)\\s+command:(\\S+)\\sCN:(\\S*)\\s");
		
		BufferedInputStream in =
		    new BufferedInputStream(m_socket.getInputStream(),
					    buffer.length);

		// Read a buffer full.
		int bytesRead = in.read(buffer);

		String line =
		    bytesRead > 0 ?
		    new String(buffer, 0, bytesRead) : "";

		Matcher userPwdMatcher =
		    userPwdPattern.matcher(line);

		// parse username and pwd
		if (userPwdMatcher.find()) {
		    String password = userPwdMatcher.group(1);

		    /* Authenticate the user.			
			 * Read hash from pwdFile and use BCrypt lib function
			 * to determine if input password is correct.
			 */
			BufferedReader br = null;
			String storedhash = "";

			try {
				br = new BufferedReader(new FileReader("pwdFile"));
				storedhash = br.readLine();
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			boolean authenticated;
			if (BCrypt.checkpw(password, storedhash)){
				System.out.println("It matches");
				authenticated = true; 
			}else{
				System.out.println("It does not match");
				authenticated = false; 
			}


		    // if authenticated, do the command
		    if( authenticated ) {
				String command = userPwdMatcher.group(2);
				String commonName = userPwdMatcher.group(3);

				doCommand( command );
		    }else{
				sendString("Incorrect password. Please try again.");
				m_socket.close();
			}
		}	
	    }
	    catch( InterruptedIOException e ) {
	    }
	    catch( Exception e ) {
			e.printStackTrace();
	    }
	}
    }

    private void sendString(final String str) throws IOException {
		PrintWriter writer = new PrintWriter( m_socket.getOutputStream() );
		writer.println(str);
		writer.flush();
    }
    
    private void doCommand( String cmd ) throws IOException {

		// TODO(cs255): instead of greeting admin client, run the indicated command
		
		if(cmd.equals("shutdown")){
			sendString("Shutting down...");
			System.exit(0);			
		}else if(cmd.equals("stats")){
			int cons = m_engine.getNumConnectRequests();
			sendString("CONNECT requests: "+cons);
		}else {
			sendString("Cmd not correct");
		}

		m_socket.close();
	
    }

}

/**
 * CzechIdM
 * Copyright (C) 2014 BCV solutions s.r.o., Czech Republic
 * 
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License 2.1 as published by the Free Software Foundation;
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free 
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, 
 * Boston, MA 02110-1301 USA
 * 
 * You can contact us on website http://www.bcvsolutions.eu.
 */

package eu.bcvsolutions.idm.connector.ssh;


import java.io.IOException;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;

import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.UserInfo;

/**
 * Třída zajišťující SSH spojení s koncovým systémem.
 * 
 * @author Jaromír Mlejnek 
 */
public class SSHConnection {

	private static final Log log = Log.getLog(SSHConnection.class);	
	
	private SSHConfiguration config;
	private Session session;
	
	/**
	 * Konstruktor třídy SSHConnection.
	 * 
	 * @param cfg konfigurace, tj. instance třídy SSHConfiguration
	 * @throws Exception
	 */
	public SSHConnection(SSHConfiguration cfg) throws Exception {
		if (cfg == null) {
			throw new Exception("Configuration not set");
		}    	
		config = cfg;    	    	    	    
	} 
	
	/**
	 * Metoda pro vytvoření spojení s koncovým systémem. Pokud je uveden privátní klíč, tak
	 * se implicitně použije pro autentizaci. Jinak se použije dvojice uživatelské jméno a
	 * heslo. Pokud je uveden otisk veřejného klíče serveru, ke kterému se připojujeme, tak
	 * se použije pro jeho verifikaci.
	 *  
	 * @return Instance třídy Session. 
	 */
	public Session startConnection() {		
		String privateKey = asString(config.getPrivkey());    	    	    	
		try {    		
			if (!StringUtil.isBlank(privateKey)) {				
				//Private key used for authentication
				log.info("Private key used for authentication.");
				createSSHConnectionWithPrivateKey(privateKey, config.getPrivkeyPassword());
			} else {
				//Authentication via password
				log.info("Authentication via password.");
				createSSHConnectionWithPassword(config.getPassword());
			}
		    	
			session.connect(SSHConfiguration.CONNECTION_TIMEOUT);					
			log.info("Succesfull connection.");
		} catch (Exception ex) {
			if (ex instanceof IOException) {
				log.warn("IOException caught: " + ex.getMessage());
			} else {
				log.error("Connecting to server failed. {0}",ex.getMessage());
				throw new ConnectionFailedException("Connecting to server failed.");
			}
		} finally {
			//clear user password
			session.setPassword("");
		}
		return session;
	}
    
    /**
     * Metoda slouží pro vytvořeni SSH spojení s koncovým systémem při autentizaci 
     * uživatelským jménem a heslem.
     * 
     * @param password heslo obsažené v instanci třídy GuardedString.
     * @throws JSchException
     */
    private void createSSHConnectionWithPassword(final GuardedString password) throws JSchException {    	    	    	
    	JSch jsch = new JSch();    	
    	session = createSession(jsch);    	
    	session.setPassword(asString(password));		
    	
    	setHostHashCheckingIfNeeded(jsch, session);				    	
    }
    
    
    /**
     * Metoda slouží k vytvoření SSH spojení s koncovým systémem při autentizaci 
     * uživatelským jménem a heslem.  
     * 
     * @param privateKey privátní klíč uživatele (uzožen v jednom String řetezci).
     * @param keyPassword heslo k privátnímu klíči, pokud je uvedeno.
     * @throws JSchException
     */
    private void createSSHConnectionWithPrivateKey(String privateKey, final GuardedString keyPassword) throws JSchException {    	    	    	       	
    	privateKey = privateKey.replaceFirst("\\n(DEK-Info:[^\\n]+\\n)([^\\r\\n]+)", "$1\n$2");    	        	    	    	    	    	
    	
    	String hostkey = asString(config.getHostkey());
    	String username = config.getUsername();
    	
    	JSch jsch = new JSch();
    	
    	session = createSession(jsch);
  
    	//radek nize je tu kvuli tomu, aby se preskakovala moznost autentizace gssapi-with-mic,
    	//ktera v tomto pripade stejne nemuze uspet a zapisuje do logu vyjimku
    	session.setConfig("PreferredAuthentications","publickey,keyboard-interactive,password");
    	
    	
    	//Nacteme si pripadne heslo ke klici a otisk verejneho klice serveru.
    	boolean isKeyPasswd = (StringUtil.isBlank(asString(keyPassword))) ? false : true;
    	boolean isHostKey = (StringUtil.isBlank(hostkey)) ? false : true;    	    
    	
    	if (!isKeyPasswd) {
    		if (!isHostKey) {    			
    			log.info("Use private key - no key password, no host key.");    			
    			jsch.addIdentity(username, privateKey.getBytes(), null, null);
    		} else {
    			log.info("Use private key - no key password, specified host key.");    			
    			jsch.addIdentity(username, privateKey.getBytes(), hostkey.getBytes(), null);
    		}    	
    	}  else {
    		if (!isHostKey) {
    			log.info("Use private key - with key password, no host key.");
    			jsch.addIdentity(username, 
    					privateKey.getBytes(), null, asString(keyPassword).getBytes());
    		} else {
    			log.info("Use private key - with key password, specified host key.");
        		jsch.addIdentity(username, privateKey.getBytes(), 
        				hostkey.getBytes(), asString(keyPassword).getBytes());
    		}
    	}    	
    	
    	setHostHashCheckingIfNeeded(jsch, session);    	    	
    }
    
    /**
     * Metoda pro vytvoření relace. Je nutné, aby bylo uvedeno uživatelské jméno, 
     * adresa k serveru a číslo portu. 
     * 
     * @param jsch
     * @return Vytvořenou relaci.
     * @throws JSchException
     */
    private Session createSession(JSch jsch) throws JSchException {    	
    	Session session = jsch.getSession(config.getUsername(), 
    			config.getHost(), config.getPort());
    	return session;
    }
        
    /**
     * Metoda zajišťující kontrolu otisku veřejného klíče (pokud je zadaný).
     *  
     * @param jsch
     * @param session Relace, pro kterou se 
     */
    private void setHostHashCheckingIfNeeded(JSch jsch, Session session) {        
        String hostKeyFingerPrint = asString(config.getHostkey());    	    	
        
        if (!StringUtil.isBlank(hostKeyFingerPrint)) {        	
            HostFingerPrints fingerPrints = new HostFingerPrints(jsch);
            session.setConfig("StrictHostKeyChecking", "yes");
            fingerPrints.addFingerPrint(hostKeyFingerPrint);  
            jsch.setHostKeyRepository(fingerPrints);
        } else {
            session.setConfig("StrictHostKeyChecking", "no");
        }
    }
    
    /**
     * Metoda navracející instanci třídy SSHConfiguration (konfigurační třídy).
     * 
     * @return Instance třídy SSHConfiguration.
     */
    public SSHConfiguration getConfiguration() {
		return this.config;
	}        
	
	/**
	 * Metoda pro ukončení spojení.
	 * {@inheritDoc}
	 */
	public void dispose() {
		log.info("Dispose connection.");    	
		if (session != null) {
			session.disconnect();
		}
	}
	
	/**
	 * Metoda testující navázané spojení.
	 * {@inheritDoc}
	 */
	public void test() {
		config.validate();    	
		startConnection();
		dispose();
	}
    
    /**
     * Statická metoda, která slouží pro transformaci různých objektů na String.
     * 
     * @param object
     * @return 
     * Transformace:
     * 	GuardedString	- transformace na heslo ve Stringu.
     * 	String[]		- transformace na String, jednotlive radky pole jsou oddleny "\n".
     * 	Object 			- transformace objektu na String metodou toString.
     *  jinak			- jinak navrací null. 
     */
    public static String asString(Object object) {    	    	
        if (object instanceof GuardedString) {
            GuardedString guarded = (GuardedString)object;            
            GuardedStringAccessor accessor = new GuardedStringAccessor();
            guarded.access(accessor);
            char[] result = accessor.getArray();
            return new String(result);
        } else if (object instanceof String [] ) {
        	//Transformuje pole Stringu do jednoho Stringu.
        	StringBuilder st = new StringBuilder();
        	String item = null;
        	
            String[] array = (String[]) object;
            for (int i = 0; i < array.length; i++) {
            	item = array[i];
            	if (item == null) {
            		continue;
            	}            	
            	st.append(item);
            	st.append("\n");
            }
            return st.toString();        	        
        } else if (object != null) {
            return object.toString();
        } else {
        	return null;
        }     
    }
       
        
    static class HostFingerPrints implements HostKeyRepository {

        protected JSch jsch;
        protected String fingerPrint;

        public HostFingerPrints(JSch jsch) {
            this.jsch = jsch;
        }

        public void addFingerPrint(String fingerPrint) {
            this.fingerPrint = fingerPrint;
        }

        public int check(String arg0, byte[] arg1) {
            try {
                HostKey hostKey = new HostKey(arg0, arg1);
                String hostKeyFingerPrint = hostKey.getFingerPrint(this.jsch);
                if (hostKeyFingerPrint.equalsIgnoreCase(this.fingerPrint)) {
                    return HostKeyRepository.OK;
                } else {
                    return HostKeyRepository.CHANGED;
                }
            } catch (JSchException ex) {
                throw new RuntimeException(ex);
            }
        }	

        public void add(HostKey arg0, UserInfo arg1) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        public void remove(String arg0, String arg1) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        public void remove(String arg0, String arg1, byte[] arg2) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        public String getKnownHostsRepositoryID() {
            return null;
        }

        public HostKey[] getHostKey() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        public HostKey[] getHostKey(String arg0, String arg1) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

    }
    
}

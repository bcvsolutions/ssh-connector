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

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;	

/**
 * Třída specifikující konfiguraci SSH konektoru.
 * 
 * @author Jaromír Mlejnek
 */
public class SSHConfiguration extends AbstractConfiguration {			    
       
    public static final int DEFAULT_PORT = 22;    
    public static final char DELIMITER = ';'; 
    public static final char DEFAULT_MULTIATTRIBUTE_SEPARATOR = ',';
    public static final int CONNECTION_TIMEOUT = 10000;  
    public static final String DEFAULT_EXCAPE_MODE = SSHMessages.SSH_ESCAPE_MODE_DOUBLED;
    
    private String host;
    private int port = DEFAULT_PORT;        
    private String username;
    private GuardedString password;
    
    private String[] privkey;
    private GuardedString privkeyPassword;
    private String[] hostkey;
    
    private String user;
    private String createUser;
    private String deleteUser;
    private String enableUser;
    private String disableUser;
    private String updateUser;
    private String authenticate;
    
    private String group;    
    private String createGroup;
    private String deleteGroup;
    private String updateGroup;
    
    private String listObjects;
    private String attributesSchema;
    
    private String escapeMode = DEFAULT_EXCAPE_MODE;
    private String[] multiValueAttributes;
    private char multiValueAttributesSeparator = DEFAULT_MULTIATTRIBUTE_SEPARATOR;
    
    //!!! CO SE BUDE MUSET VZDY ZADAVAT !!!
    
    @ConfigurationProperty(order = 1,
    		displayMessageKey = "SSH_HOST_NAME",
    		helpMessageKey = "SSH_HOST_HELP",
    		required = true)
    public String getHost() {
		return host;
	}
    
    @ConfigurationProperty(order = 2,
    		displayMessageKey = "SSH_PORT_NAME",
    		helpMessageKey = "SSH_PORT_HELP",
    		required = true)
    public int getPort() {
		return port;
	}
    
	@ConfigurationProperty(order = 3,
			displayMessageKey = "SSH_USER_NAME",
			helpMessageKey = "SSH_USER_HELP",
			required = true)
	public String getUsername() {
		return username;
	}
        
    @ConfigurationProperty(order = 4,
    		displayMessageKey = "SSH_USER_PASSWORD_NAME",
    		helpMessageKey = "SSH_USER_PASSWORD_HELP",
    		confidential = true)
    public GuardedString getPassword() {
		return password;
	}
    
    @ConfigurationProperty(order = 5,
    		displayMessageKey = "SSH_PRIVATE_KEY_NAME",
    		helpMessageKey = "SSH_PRIVATE_KEY_HELP")
    public String[] getPrivkey() {
		return privkey;
	}
    
    @ConfigurationProperty(order = 6,
    		displayMessageKey = "SSH_PRIVATE_KEY_PASSWORD_NAME",
    		helpMessageKey = "SSH_PRIVATE_KEY_PASSWORD_HELP",
    		confidential = true)
    public GuardedString getPrivkeyPassword() {
		return privkeyPassword;
	}
    
    @ConfigurationProperty(order = 7,
    		displayMessageKey = "SSH_HOSTKEY_NAME",
    		helpMessageKey = "SSH_HOSTKEY_HELP")
    public String[] getHostkey() {
		return hostkey;
	}
    
    //SKRIPTY
    @ConfigurationProperty(order = 8,
    		displayMessageKey = "SSH_SCRIPT_GETUSER_NAME",
    		helpMessageKey = "SSH_SCRIPT_GETUSER_HELP")
    public String getUser() {
		return user;
	}
    
    @ConfigurationProperty(order = 9,
    		displayMessageKey = "SSH_SCRIPT_CREATEUSER_NAME",
    		helpMessageKey = "SSH_SCRIPT_CREATEUSER_HELP")
    public String getCreateUser() {
		return createUser;
	}
    
    @ConfigurationProperty(order = 10,
    		displayMessageKey = "SSH_SCRIPT_DELETEUSER_NAME",
    		helpMessageKey = "SSH_SCRIPT_DELETEUSER_HELP")
    public String getDeleteUser() {
		return deleteUser;
	}
    
    @ConfigurationProperty(order = 11,
    		displayMessageKey = "SSH_SCRIPT_ENABLEUSER_NAME",
    		helpMessageKey = "SSH_SCRIPT_ENABLEUSER_HELP")
    public String getEnableUser() {
		return enableUser;
	}
    
    @ConfigurationProperty(order = 12,
    		displayMessageKey = "SSH_SCRIPT_DISABLEUSER_NAME",
    		helpMessageKey = "SSH_SCRIPT_DISABLEUSER_HELP")
    public String getDisableUser() {
		return disableUser;
	}
    
    @ConfigurationProperty(order = 13,
    		displayMessageKey = "SSH_SCRIPT_UPDATEUSER_NAME",
    		helpMessageKey = "SSH_SCRIPT_UPDATEUSER_HELP")
    public String getUpdateUser() {
		return updateUser;
	}
    
    @ConfigurationProperty(order = 14,
    		displayMessageKey = "SSH_SCRIPT_GETGROUP_NAME",
    		helpMessageKey = "SSH_SCRIPT_GETGROUP_HELP")
    public String getGroup() {
		return group;
	}
    
    @ConfigurationProperty(order = 15,
    		displayMessageKey = "SSH_SCRIPT_CREATEGROUP_NAME",
    		helpMessageKey = "SSH_SCRIPT_CREATEGROUP_HELP")
    public String getCreateGroup() {
		return createGroup;
	}
    
    @ConfigurationProperty(order = 16,
    		displayMessageKey = "SSH_SCRIPT_DELETEGROUP_NAME",
    		helpMessageKey = "SSH_SCRIPT_DELETEGROUP_HELP")
    public String getDeleteGroup() {
		return deleteGroup;
	}
    
    @ConfigurationProperty(order = 17,
    		displayMessageKey = "SSH_SCRIPT_UPDATEGROUP_NAME",
    		helpMessageKey = "SSH_SCRIPT_UPDATEGROUP_HELP")
    public String getUpdateGroup() {
		return updateGroup;
	}
    
    @ConfigurationProperty(order = 18,
    		displayMessageKey = "SSH_SCRIPT_LISTOBJECTS_NAME",
    		helpMessageKey = "SSH_SCRIPT_LISTOBJECTS_HELP")
    public String getListObjects() {
		return listObjects;
	}
    
    @ConfigurationProperty(order = 19,
    		displayMessageKey = "SSH_SCRIPT_ATTRIBUTESLIST_NAME",
    		helpMessageKey = "SSH_SCRIPT_ATTRIBUTESLIST_HELP")
    public String getAttributesSchema() {
		return attributesSchema;
	}
    
    @ConfigurationProperty(order = 20,
    		displayMessageKey = "SSH_SCRIPT_ESCAPEMODE_NAME",
    		helpMessageKey = "SSH_SCRIPT_ESCAPEMODE_HELP",
    		required = true)
    public String getEscapeMode() {
		return escapeMode;
	}
    

    @ConfigurationProperty(order = 21,
    		displayMessageKey = "SSH_SCRIPT_MULTIVALUEATT_NAME",
    		helpMessageKey = "SSH_SCRIPT_MULTIVALUEATT_HELP")
    public String[] getMultiValueAttributes() {
		return multiValueAttributes;
	}
    

    @ConfigurationProperty(order = 22,
    		displayMessageKey = "SSH_SCRIPT_MULTIVALUEATTSEPARATOR_NAME",
    		helpMessageKey = "SSH_SCRIPT_MULTIVALUEATTSEPARATOR_HELP")
    public char getMultiValueAttributesSeparator() {
		return multiValueAttributesSeparator;
	}       
    
    @ConfigurationProperty(order = 23,
    		displayMessageKey = "SSH_SCRIPT_AUTHENTICATE_NAME",
    		helpMessageKey = "SSH_SCRIPT_AUTHENTICATE_HELP")
    public String getAuthenticate() {
		return authenticate;
	}
    
    public void setHost(String host) {
		this.host = host;
	}
    
    public void setPort(int port) {
		this.port = port;
	}
    
    public void setUsername(String username) {
		this.username = username;
	}
    
    public void setPassword(GuardedString password) {
		this.password = password;
	}
    
    public void setPrivkey(String[] privkey) {
		this.privkey = privkey;
	}
    
    public void setPrivkeyPassword(GuardedString privkey_password) {
		this.privkeyPassword = privkey_password;
	}
    
    public void setHostkey(String[] hostkey) {
		this.hostkey = hostkey;
	}
    
    public void setUser(String user) {
		this.user = user;
	}
    
    public void setCreateUser(String createUser) {
		this.createUser = createUser;
	}
    
    public void setDeleteUser(String deleteUser) {
		this.deleteUser = deleteUser;
	}
    
    public void setEnableUser(String enableUser) {
		this.enableUser = enableUser;
	}
    
    public void setDisableUser(String disableUser) {
		this.disableUser = disableUser;
	}
    
    public void setUpdateUser(String updateUser) {
		this.updateUser = updateUser;
	}
    
    public void setAuthenticate(String authenticate) {
    	this.authenticate = authenticate;
    }
    
    public void setGroup(String group) {
		this.group = group;
	}
    
    public void setCreateGroup(String createGroup) {
		this.createGroup = createGroup;
	}
    
    public void setDeleteGroup(String deleteGroup) {
		this.deleteGroup = deleteGroup;
	}
    
    public void setUpdateGroup(String updateGroup) {
		this.updateGroup = updateGroup;
	}
    
    public void setListObjects(String listObjects) {
		this.listObjects = listObjects;
	}
    
    public void setAttributesSchema(String attributesSchema) {
		this.attributesSchema = attributesSchema;
	}
    
    public void setEscapeMode(String escapeMode) {
		this.escapeMode = escapeMode;
	}
    
    public void setMultiValueAttributes(String[] multiValueAttributes) {
		this.multiValueAttributes = multiValueAttributes;
	}
    
    public void setMultiValueAttributesSeparator(
			char multiValueAttributesSeparator) {
		this.multiValueAttributesSeparator = multiValueAttributesSeparator;
	}
       
    
    /**
     * Implicitní konstruktor.
     */
    public SSHConfiguration() {     	
    }
    
    /**
     * Vrací a formátuje zprávu.
     * 
     * @param key klíč pro výběr zprávy z "Message.properties".
     * @return Zpráva.
     */
    public String getMessage(String key) {
    	return getConnectorMessages().format(key, key);
    }
    
    /**
     * Vrací a formátuje zprávu.
     * 
     * @param key klíč pro výběr zprávy z "Message.properties"
     * @param objects parametry
     * @return Zpráva.
     */
    public String getMessage(String key, Object... objects) {
    	return getConnectorMessages().format(key, key, objects);
    }
    
	/**
	 * Validuje konfiguraci konektoru. Kontroluje, zda jsou nastaveny všechny potřebné parametry.
	 * Implementace by měla pouze kontrolovat syntaktickou stránku, tjn. jestli jsou vsechny potřebné
	 * parametry "well-formed". Neměla by se snažit ověřovat dostupnost zdroju, napr. pripojovat se k nim. 
	 */
	@Override
	public void validate() {    	
		if (StringUtil.isBlank(getHost())) {
			throw new IllegalArgumentException("Hostname must be set.");
		}    	
		if (getPort() < 0 || getPort() >= 65535) {
			throw new IllegalArgumentException("Port must be in range between 1 to 65535.");
		}
		if (StringUtil.isBlank(getUsername())) {
			throw new IllegalArgumentException("Username must be specified.");
		} 
		if (!getEscapeMode().equals(SSHMessages.SSH_ESCAPE_MODE_DOUBLED) && !getEscapeMode().equals(SSHMessages.SSH_ESCAPE_MODE_BACKSLASH)) {
			throw new IllegalArgumentException("Escape mode must be BACKSLASH or DOUBLED");
		}    	
	}    
    
}

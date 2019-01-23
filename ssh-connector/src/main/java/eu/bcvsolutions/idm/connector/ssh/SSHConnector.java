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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.operations.ScriptOnResourceApiOp;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfo.Flags;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.ScriptContext;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.AuthenticateOp;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.ScriptOnResourceOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateOp;

import com.csvreader.CsvReader;
import com.csvreader.CsvWriter;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.Session;

import eu.bcvsolutions.idm.connector.ssh.filters.SSHGroupFilterTranslator;
import eu.bcvsolutions.idm.connector.ssh.filters.SSHUserFilterTranslator;
	
/**
 * Třída implementující funkcionalitu poskytovanou SSH konektorem.
 * 
 * @author Jaromír Mlejnek
 */
@ConnectorClass(displayNameKey="SSH_Universal_Connector",
		configurationClass = SSHConfiguration.class)
public class SSHConnector implements Connector, CreateOp, DeleteOp, SearchOp<String>, 
	UpdateOp, SchemaOp, TestOp, AuthenticateOp, ScriptOnResourceApiOp, ScriptOnResourceOp {
	
	private static Schema schema;        
	private static final String ENCODING = "UTF-8";
	
	private SSHConfiguration config;
	private SSHConnection connection;    
	
	private List<String> multiValueAttribs; 
	
	//Logger
	Log log = Log.getLog(SSHConnector.class);
	
	/**
	 * Implicitní konstruktor.
	 */
	public SSHConnector() {
	}    
	
	/**
	 * Metoda navracející konfiguraci.
	 */
	public Configuration getConfiguration() {
	    return this.config;
	}
	
	/**
	 * Metoda pro načtení konfigurace a inicializaci spojení. 
	 */
	public void init(Configuration cfg) {    	
	    config = (SSHConfiguration)cfg;
	    try {
	    	connection = new SSHConnection(config);        	
	    } catch (Exception ex){
	    	log.error("Exception during initialization.");
	    	ex.printStackTrace();
	    }
	    
	    if (config.getMultiValueAttributes() == null || config.getMultiValueAttributes().length == 0) {
	    	multiValueAttribs = new ArrayList<String>();
	    } else {
	    	multiValueAttribs = Arrays.asList(config.getMultiValueAttributes());
	    }          
	}
	
	/**
	 * Metoda pro ukončení spojení.
	 */
	public void dispose() {    	    
		if (connection != null) {
			connection.dispose();    		
		}
	}
	
	/**
	 * Metoda spouštějící test spojení. Pokud není spojení s koncovým systémem navázáno, tak 
	 * metoda vyhodí výjimku.
	 */
	public void test() {    	
		log.info("SSHConnector - test");
		connection.test();   	
	}    
    
	/**
	 * Metoda pro zakládání objektu daného typu (ACCOUNT nebo GROUP) na koncovém systému.
	 */
	public Uid create(ObjectClass oclass, Set<Attribute> attrs, OperationOptions options) {    	    	    	
		String operationName = ""; 
		String pathToScript = "";
	    Uid returnUid = null;    	        
	  
		if (oclass.is(ObjectClass.ACCOUNT_NAME)) {
			operationName = SSHMessages.SSH_CREATEUSER;   		
			pathToScript = config.getCreateUser();    		
			checkPathToScript(pathToScript, operationName);    		
			returnUid = createOrUpdateUser(operationName, pathToScript, attrs);
			
		} else if (oclass.is(ObjectClass.GROUP_NAME)) {
			operationName = SSHMessages.SSH_CREATEGROUP;
			pathToScript = config.getCreateGroup();
			checkPathToScript(pathToScript, operationName);
			returnUid = createOrUpdateGroup(operationName, pathToScript, attrs);
		} 
	                   
	    return returnUid;     	
	}      
	
	/**
	 * Metoda provádí dle názvu operace, cesty ke skriptu a zadaných atributů příslušnou operaci s 
	 * uživatelským účtem.
	 *  
	 * @param operationName název prováděné operace.
	 * @param pathToScript cesta k danému skriptu. 
	 * @param attrs množina zadaných atributů. 
	 * @return Uid uživatelského účtu, který se vytvořil nebo měnil.
	 */
	private Uid createOrUpdateUser(String operationName, String pathToScript, Set<Attribute> attrs) {
		StringBuffer userHeader = new StringBuffer();
	    List<String> dataForUserLine = new ArrayList<String>();
	           
		Attribute attrib = null;
		Iterator<Attribute> it = attrs.iterator();
		while (it.hasNext()) {
			attrib = it.next();
			if (attrib.is(Name.NAME)) {							
				//TODO Musime vedet nazev atributu - JAK UDELAT JINAK?
				String name = getName(attrib);
				userHeader.append(SSHMessages.SSH_HEADER_ACCOUNTID);
				userHeader.append(SSHConfiguration.DELIMITER);
				dataForUserLine.add(name);	
				
				//Budeme moci odstranit, protoze o hesla se postara operace "getAttributeValue(attrib)"
				//na radce 184.
			} else if (attrib.is(OperationalAttributes.PASSWORD_NAME)) {				
		        //TODO Musime vedet nazev atributu - JAK UDELAT JINAK?
		        userHeader.append(SSHMessages.SSH_HEADER_PASSWORD);
		        userHeader.append(SSHConfiguration.DELIMITER);
		        dataForUserLine.add(getPassword(attrib));

			} else {
				userHeader.append(attrib.getName());
	    		userHeader.append(SSHConfiguration.DELIMITER);
	    		dataForUserLine.add(getAttributeValue(attrib));
			}    			
		}
		//Odstranime delimiter na konci radku
		userHeader = removeLastChar(userHeader);
		
		String scriptParams = createCommandCSV(operationName, userHeader, dataForUserLine);		
		String result = runCommand(pathToScript, scriptParams);	
		
		String accountUid = "";
		try {
			CsvReader reader = CsvReader.parse(result);
			reader.setDelimiter(SSHConfiguration.DELIMITER);
			reader.setEscapeMode(getCsvReaderMode());
			reader.readHeaders();
			reader.readRecord();
			accountUid = reader.get(0);
		} catch (IOException ioExc) {
			log.error("Exception during read from CSV file. \nError: {0}", ioExc.getMessage());
		} 	
		if (StringUtil.isBlank(accountUid)) {
			return null;
		}
		return new Uid(accountUid);
	}    
    
    /**
     * Metoda provádí dle názvu operace, cesty ke skriptu a zadaných atributům příslušnou operaci se 
     * skupinami.
     *  
     * @param operationName název prováděné operace.
     * @param pathToScript cesta k danému skriptu. 
     * @param attrs množina zadaných atributů. 
     * @return Uid skupiny, která se vytvořila nebo měnila.
     */
    private Uid createOrUpdateGroup(String operationName, String pathToScript, Set<Attribute> attrs) {
    	StringBuffer userHeader = new StringBuffer();
        List<String> dataForUserLine = new ArrayList<String>();
        
		Attribute attrib = null;
		Iterator<Attribute> it = attrs.iterator();
		while (it.hasNext()) {
			attrib = it.next();
			if (attrib.is(Name.NAME)) {
				//TODO Musime vedet nazev atributu - JAK UDELAT JINAK?
				String name = getName(attrib);
				userHeader.append(SSHMessages.SSH_HEADER_GROUP_NAME);
				userHeader.append(SSHConfiguration.DELIMITER);
				dataForUserLine.add(name);							   		     
			} else {
				userHeader.append(attrib.getName());
        		userHeader.append(SSHConfiguration.DELIMITER);
        		dataForUserLine.add(getAttributeValue(attrib));
			}    			
		}
		//Odstranime delimiter na konci radku
		userHeader = removeLastChar(userHeader);
		
		String scriptParams = createCommandCSV(operationName, userHeader, dataForUserLine);				
		String result = runCommand(pathToScript, scriptParams);
		String accountUid = "";
		try {
			CsvReader reader = CsvReader.parse(result);
			reader.setDelimiter(SSHConfiguration.DELIMITER);
			reader.setEscapeMode(getCsvReaderMode());
			reader.readHeaders();
			reader.readRecord();			
		} catch (IOException ioExc) {
			log.error("Exception during read from CSV file. \nError: {0}", ioExc.getMessage());
		} 
		if (StringUtil.isBlank(accountUid)) {
			return null;
		}
		return new Uid(accountUid);
    }
    
    /**
     * Metoda pro vytvoření příkazů ve formátu CSV. Tyto příkazy konektor předává příslušným skriptům
     * na koncovém systému, kde se tyto příkazy provádí.    
     * 
     * @param operationName název prováděné operace na koncovém systému.
     * @param userHeader CSV hlavička.
     * @param dataForUserLine hodnoty příslušných atributů.
     * @return Příkaz v podobě CSV textu, který očekávají skripty koncového systému. 
     */
    private String createCommandCSV(String operationName, StringBuffer userHeader, List<String> dataForUserLine) {
    	String result = "";
        try {
        	String userLine = getCSVLineFromStrings(dataForUserLine.toArray(new String [] {}));
        	result = String.format("%s\n%s\n%s\n", operationName, userHeader.toString(), userLine);        	        	
        } catch (IOException ioEx) {        	
        	log.error("Error during creation CSV.");
        }        
        return result;
    } 
    
    /**
     * Metoda navrací hodnotu předávaného atributu (instance třídy Attribute). Pokud se jedná
     * o jednohodnotový atribut, tak se předá přímo jeho hodnota, pokud jde o vícehodnotový atribut,
     * tak se navratí hodnoty oddělené separátorem (uveden v konfiguraci).  
     * 
     * @param attr daný atribut.
     * @return Hodnota atributu v podobě String řetezce.
     */
    private String getAttributeValue(Attribute attr) {
    	StringBuilder st = new StringBuilder();
    	Iterator<Object> it = attr.getValue().iterator();
    	Object obj = null;
    	while (it.hasNext()) {
    		obj = it.next();
    		if (obj instanceof GuardedString) {    			
    			st.append(SSHConnection.asString(obj));
    			st.append(config.getMultiValueAttributesSeparator());
    		} else if (obj != null) {
    			st.append(obj.toString());
    			st.append(config.getMultiValueAttributesSeparator());
    		}    		    		
    	}
    	//Odstranime posledni znak (separator).
    	return removeLastChar(st.toString()); 
    }
    
    /**
     * Metoda navrací rětězec reprezentující hodnotu instance třídy Name.
     * 
     * @param attrib předávaný atribut.
     * @return Uživatelské jméno (Name). 
     */
    private String getName(Attribute attrib) {
    	if (!attrib.is(Name.NAME)) {
    		return null;
    	}
    	final Name name = (Name) attrib;
		if (name == null || StringUtil.isBlank(name.getNameValue())) {
            throw new IllegalArgumentException("Name attribute is missing.");
        }
		return name.getNameValue();
    }
    
    /**
     * Metoda navrací heslo obsažené v atributu (instance třídy Attribute).
     * 
     * @param attribute atribut s heslem.
     * @return Heslo v podobě String řetězce.
     */
    private String getPassword(Attribute attribute) {
    	GuardedString password = null;    		        
        if (attribute != null) {
        	password = AttributeUtil.getGuardedStringValue(attribute);        	
        }
        return SSHConnection.asString(password);
    }
    
    /**
     * Metoda pro smazání objektu (ACCOUNT nebo GROUP) na koncovém systému.
     */
    public void delete(ObjectClass objClass, Uid uid, OperationOptions options) {    	
    	String operationName = ""; 
    	String pathToScript = "";
    	StringBuffer userHeader = new StringBuffer();
        List<String> dataForUserLine = new ArrayList<String>();
        
    	if (objClass.is(ObjectClass.ACCOUNT_NAME)) {
    		operationName = SSHMessages.SSH_DELETEUSER;
    		pathToScript = config.getDeleteUser();
    		userHeader.append(SSHMessages.SSH_HEADER_ACCOUNTID);
    	} else if (objClass.is(ObjectClass.GROUP_NAME)) {
    		operationName = SSHMessages.SSH_DELETEGROUP;
    		pathToScript = config.getDeleteGroup();
    		userHeader.append(SSHMessages.SSH_HEADER_GROUP_NAME);
    	} else {
    		return;
    	}    	
    	checkPathToScript(pathToScript, operationName);
    	
    	String name = uid.getUidValue();    	
    	dataForUserLine.add(name);
    	String scriptParams = createCommandCSV(operationName, userHeader, dataForUserLine);		    	
    	runCommand(pathToScript, scriptParams);
    }
    
    /**
     * Matoda pro aktualizaci objektu na koncovém systému.
     */
    public Uid update(ObjectClass objclass, Uid uid, Set<Attribute> replaceAttributes, OperationOptions options) {
    	String operationName = ""; 
    	String pathToScript = "";
        Uid returnUid = null;        
    	Set<Attribute> attribs = new HashSet<Attribute>();
    	
    	//Pridame atribut identifikujici objekt (ucet nebo skupinu)    	
    	attribs.add(new Name(uid.getUidValue()));
		attribs.addAll(replaceAttributes);
		        
    	if (objclass.is(ObjectClass.ACCOUNT_NAME)) {
    		operationName = SSHMessages.SSH_UPDATEUSER;    		
    		pathToScript = config.getUpdateUser();  
    		checkPathToScript(pathToScript, operationName);    		    		
    		    		    		    		
    		returnUid = createOrUpdateUser(operationName, pathToScript, attribs);    		
    	} else if (objclass.is(ObjectClass.GROUP_NAME)) {
    		operationName = SSHMessages.SSH_UPDATEGROUP;
    		pathToScript = config.getUpdateGroup();
    		checkPathToScript(pathToScript, operationName);
    		
    		returnUid = createOrUpdateGroup(operationName, pathToScript, attribs);
    	}                       
    	
        return returnUid;    	
    }
    
	/**
	 * Metoda slouží pro spuštění dotazu nad objekty koncového systému.
	 */
	public void executeQuery(ObjectClass oclass, String query, ResultsHandler handler, OperationOptions options) {    	    	
		ConnectorObject object = null;
		if (query == null) {
			//Vylistovat vsechny objekty dane tridy.
			Session session = connection.startConnection();
			Iterator<Name> it = getAllObjectNames(oclass).iterator();
			Name m = null;
			// String scriptParams;
			try {
				while (it.hasNext()) {
					m = it.next();
					// pri listovani uzivatelu nepotrebujeme volat dodatecny get na ucet
					// rovnou tedy vytvorime connector object
					ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
					builder.setUid(m.getNameValue());
					builder.setObjectClass(oclass);
					builder.addAttribute(AttributeBuilder.build(Name.NAME, m.getNameValue()));
					handler.handle(builder.build());
					
					// scriptParams = createGetQuery(oclass, m.getNameValue());				
					// object = getConnectorObject(oclass, scriptParams, session);						
					// if (object != null) {
					//     handler.handle(builder.build());
					// }							
				}
			} catch (ConnectorException ex) {
				throw new ConnectorException(ex.getMessage());
			} finally {
				if (session != null && session.isConnected()) {
					session.disconnect();
				}
			}			
		} else {
			//Vylistovat pouze zaznam odpovidajici danemu dotazu (query).			
			object = getConnectorObject(oclass, query, null);			
			if (object != null) {
				handler.handle(object);
			}
		}    	    	    	            
	}
    
    /**
     * Metoda vytváří příkaz ve formátu CSV pro vyhledání uživatele nebo skupiny daného jména.
     * 
     * @param objClass typ objektu.
     * @param name název hledaného objektu (uživatele nebo skupiny).
     * @return Příslušný GET dotaz ve formátu CSV.
     */    
	/*
    private String createGetQuery(ObjectClass objClass, String name) {
    	String operationName;
    	StringBuffer header = new StringBuffer();
    	if (objClass.is(ObjectClass.ACCOUNT_NAME)) {
    		operationName = SSHMessages.SSH_GETUSER;
    		header.append(SSHMessages.SSH_HEADER_ACCOUNTID);
    	} else if (objClass.is(ObjectClass.GROUP_NAME)) {
    		operationName = SSHMessages.SSH_GETGROUP;
    		header.append(SSHMessages.SSH_HEADER_GROUP_NAME);
    	} else {
    		throw new IllegalArgumentException("Bad object class. Must be ACCOUNT or GROUP.");    		
    	} 	    	
    	return createCommandCSV(operationName, header, Arrays.asList(name));    	
    }
    */
    
    /**
     * Metoda navrací cestu ke skriptu pro vyhledání objektu.
     * 
     * @param objClass třída objektu, pro kterou chceme nalézt cestu ke GET skriptu.
     * @return Cesta ke GET skriptu.
     */
    private String getPathToGetScript(ObjectClass objClass) {
    	String path = "";
    	String operationName = "";
    	if (objClass.is(ObjectClass.ACCOUNT_NAME)) {
    		path = config.getUser();
    		operationName = SSHMessages.SSH_GETUSER;
    	} else if (objClass.is(ObjectClass.GROUP_NAME)) {
    		path = config.getGroup();
    		operationName = SSHMessages.SSH_GETGROUP;
    	} else {
    		return null;
    	}
    	checkPathToScript(path, operationName);
    	
    	return path; 
    }
    
    /**
     * Metoda navrací seznam identifikátorů (instance třídy Name) pro danou třídu objektů
     * (ACCOUNT nebo GROUP).
     * 
     * @param objClass třída objektů, pro kterou chceme získat seznam identifikátorů.
     * @return Seznam identifikátorů v podobě listu instancí třídy Name.
     */
    private List<Name> getAllObjectNames(ObjectClass objClass) {    	    	    	    	
    	String operationName = SSHMessages.SSH_LISTOBJECTS; 
    	String pathToScript = config.getListObjects();
    	checkPathToScript(pathToScript, operationName);
    	
    	StringBuffer userHeader = new StringBuffer();
        List<String> dataForUserLine = new ArrayList<String>();                     	
    	if (objClass.is(ObjectClass.ACCOUNT_NAME)) {    		
    		dataForUserLine.add(SSHMessages.SSH_HEADER_USERS);    		
    	} else if (objClass.is(ObjectClass.GROUP_NAME)) {    		
    		dataForUserLine.add(SSHMessages.SSH_OBJECT_TYPE_GROUP);
    	} else {
    		throw new IllegalArgumentException("Bad object class. Must be ACCOUNT or GROUP.");
    	}
    	
    	userHeader.append(SSHMessages.SSH_HEADER_OBJECTTYPE);
    	String scriptParams = createCommandCSV(operationName, userHeader, dataForUserLine);
    	String resCSV = runCommand(pathToScript, scriptParams);
    	
    	//Zpracovani CSV souboru, ktery jsme obdrzeli od prislusneho skriptu.
    	List<Name> result = null;
    	try {
    		result = getObjectNamesFromCSV(objClass, resCSV);
    	} catch (IOException ioExc) {
    		log.error("Exception during read from CSV file. \nError: {0}", ioExc.getMessage());
    	}
    	
    	return result;
    }
    
    /**
     * Metoda pro získání listu identifikátorů objektů z CSV výstupu skriptu 
     * koncového systému.
     * 
     * @param objClass třída objektů.
     * @param csvText výstup skriptu ve formátu CSV.
     * @return List identifikátorů.
     * @throws IOException
     */
    private List<Name> getObjectNamesFromCSV(ObjectClass objClass, String csvText) throws IOException {
    	CsvReader reader = CsvReader.parse(csvText);
    	reader.setDelimiter(SSHConfiguration.DELIMITER);
    	reader.setEscapeMode(getCsvReaderMode());
    	reader.readHeaders();
    	
    	//Dle tridy hledaneho objektu urcime nazev hledaneho identifikatoru.
    	//TODO Pokud bychom pouzili tridu Name, tak by to bylo lehci.
    	String identName;
    	if (objClass.is(ObjectClass.ACCOUNT_NAME)) {
    		identName = SSHMessages.SSH_HEADER_ACCOUNTID;
    	} else if (objClass.is(ObjectClass.GROUP_NAME)) {
    		identName = SSHMessages.SSH_HEADER_GROUP_NAME;
    	} else {
    		throw new IllegalArgumentException("Bad object class. Must be ACCOUNT or GROUP.");
    	}
    	    	    	
    	String columnName = "";
    	String value = "";
    	List<Name> names = new ArrayList<Name>();
    	while (reader.readRecord()) {
    		//Vzdy by mel byt pouze jeden sloupec, cyklus by nemel byt nutny.    		
    		for (int i = 0; i < reader.getColumnCount(); i++) {
    			columnName = reader.getHeader(i);
									
				if (columnName.equals(identName)) {
					//Jedna se o identifikator					
					value = reader.get(i); 
					names.add(new Name(value));
					break;
				}				
			}
    	}    	
    	return names;
    }
    
    /**
     * Metoda provede příslušný GET skript (podle toho jestli se jedná o ACCOUNT nebo GROUP) a navrátí
     * connector object příslušející danámu záznamu.
     * 
     * @param objClass určuje, jestli se jedná o ACCOUNT nebo GROUP.
     * @param scriptParams parametry GET skriptu ve formátu CSV.
     * @param session session, která je použita pro provedeni příkazu, pokud je null, tak se výtvoří nová
     * pouze pro tuto metodu.
     * @return Instance třídy ConnectorObject odpovídající hledanému záznamu.
     */
    private ConnectorObject getConnectorObject(ObjectClass objClass, String scriptParams, Session session) {
    	ConnectorObjectBuilder builder = new ConnectorObjectBuilder();    	    
    	String pathToScript = getPathToGetScript(objClass);
    	if (pathToScript == null) {
    		throw new IllegalArgumentException("Bad object class. Must be ACCOUNT or GROUP.");    		
    	}
    	String result;
    	
		if (session == null) {
			//Vytvorime si novou session.
			result = runCommand(pathToScript, scriptParams);
		} else {
			//Pouzijeme danou session.
			result = runCommand(pathToScript, scriptParams, session);
		}    	
    	boolean isSetUID = false;
    	
    	CsvReader reader = CsvReader.parse(result);
    	reader.setDelimiter(SSHConfiguration.DELIMITER);
    	reader.setEscapeMode(getCsvReaderMode());
    	
    	try {
			reader.readHeaders();						
			String identName = "";
			if (objClass.is(ObjectClass.ACCOUNT_NAME)) {
				identName = SSHMessages.SSH_HEADER_ACCOUNTID;
			} else if (objClass.is(ObjectClass.GROUP_NAME)) {
				identName = SSHMessages.SSH_HEADER_GROUP_NAME;
			}			
			
			String columnName = "";
			String value = "";			
			//Mame pouze jeden zaznam, proto neiterujeme pres radky.
			reader.readRecord();
			for (int i = 0; i < reader.getColumnCount(); i++) {
				columnName = reader.getHeader(i);
				value = reader.get(i);					
				if (columnName.equals(identName)) {
					//Jedna se o identifikator, musi byt UID i Name nastaveno					
					builder.setName(value);
					builder.setUid(value);
					isSetUID = true;
				} else {
					//Ostatni atributy
					builder.addAttribute(createAttribute(columnName, value));
				}								
			}    			
    	} catch (IOException ioExc) {
    		log.error("Exception during read from CSV file. \nError: {0}", ioExc.getMessage());
		}
		
    	builder.setObjectClass(objClass);
    	if (isSetUID) {
    		return builder.build();
    	} else {
    		return null;
    	}    	
    }
    
    /**
     * Metoda vytvoří atribut zadaného jména a přiřadí mu zadanou hodnotu (hodnoty).
     * 
     * @param name jméno vytvářeného atributu.
     * @param value hodnota (hodnoty) atributu. 
     * @return Instance třídy Attribute.
     */
    private Attribute createAttribute(String name, String value) {
    	Attribute attrib = null;    	
    	if (multiValueAttribs.contains(name)) {
    		//Skript navratil multi-value atribut. Rozparsujeme ho tedy dle urceneho delimiteru
    		//a ulozime do atributu jako List.
    		String[] values = value.split(String.valueOf(config.getMultiValueAttributesSeparator()));
    		attrib = AttributeBuilder.build(name, Arrays.asList(values));
    	} else {
    		//Jedna se o obycejny (jednohodnotovy) atribut.
    		attrib = AttributeBuilder.build(name, value);
    	}
    	return attrib;
    } 
    
	/**
	 * Metoda navrací dle použité třídy objektů odpovídající filtr. 
	 */
	public FilterTranslator<String> createFilterTranslator(ObjectClass oclass, OperationOptions options) {
		if (oclass.is(ObjectClass.ACCOUNT_NAME)) {
			return new SSHUserFilterTranslator();
		} else if (oclass.is(ObjectClass.GROUP_NAME)) {
			return new SSHGroupFilterTranslator();
		}
		return null;
	}          
    
    /**
     * Metoda definující počáteční schéma atributů pro jednotlivé třídy objektů.
     * Defaultní nastavení (koncovým systémem je Linux). 
     */
    public Schema schema() {    	
    	if (schema != null) {
    		return schema;
    	}    	    
    	final SchemaBuilder schemaBuilder = new SchemaBuilder(getClass());    	
    	    	    	
    	String params = SSHMessages.SSH_ATTRIBUTESLIST + "\n";    	    	    	
    	String res  = runCommand(config.getAttributesSchema(), params);
    	
    	CsvReader reader = CsvReader.parse(res);
    	reader.setDelimiter(SSHConfiguration.DELIMITER);
    	reader.setEscapeMode(getCsvReaderMode());    	
    	
    	Set<AttributeInfo> attributesInfoSet = new HashSet<AttributeInfo>();    	    	
    	ObjectClassInfo info = null;
    	
    	try {	    	    		    		
	    	reader.readHeaders();	    	
	    	while (reader.readRecord()) {	    		
	    		attributesInfoSet.add(getAttributeInfoFromCSVReader(reader));
	    	}	    				    	
	    	
	    	info = new ObjectClassInfoBuilder().addAllAttributeInfo(attributesInfoSet).build();
    	} catch (IOException ioExc) {
    		log.error("Exception during read from CSV file. \nError: {0}", ioExc.getMessage());
    	} catch (ClassNotFoundException cnfe) {
    		log.error("Class for given attribute was not found. \nError: {0}", cnfe.getMessage());
    	}
    	
    	schemaBuilder.defineObjectClass(info);              	
    	schema = schemaBuilder.build();
    	return schema;
    }    
    
    private AttributeInfo getAttributeInfoFromCSVReader(CsvReader reader) throws IOException, ClassNotFoundException {
    	AttributeInfo attrInfo = null;
    	String attributeName, attributeType, attributeFlags;
    	    	
    	attributeName = reader.get(SSHMessages.SSH_ATTRIBUTE_NAME);
    	attributeType = reader.get(SSHMessages.SSH_ATTRIBUTE_TYPE);
    	attributeFlags = reader.get(SSHMessages.SSH_ATTRIBUTE_FLAGS);
    	
    	Set<Flags> flagSet = new TreeSet<Flags>();
    	if (attributeFlags != null && attributeFlags.length() > 0) {
    		String[] flags = attributeFlags.split(String.valueOf(config.getMultiValueAttributesSeparator()));    		
    		for (int i = 0; i < flags.length; i++ ) {
    			flagSet.add(Flags.valueOf(flags[i]));
    		}
    	}
    	
    	attrInfo = AttributeInfoBuilder.build(attributeName, Class.forName(attributeType), flagSet);    	
    	return attrInfo;
    }
    
    /**
     * Metoda provádí kontrolu, zda je vyplněna cesta ke skriptu.
     * 
     * @param path Cesta ke skriptu.
     * @param operation Název operace zajišťované daným skriptem.
     * @throws IllegalArgumentException
     */
    private void checkPathToScript(String path, String operation) throws IllegalArgumentException {
        if (StringUtil.isBlank(path)) {
        	log.error("Path to script {0} is not set.", operation);
        	throw new IllegalArgumentException();        	
        }
    }
    
    /**
     * Metoda slouží pro spouštění skriptů na koncovém systému. Každé provádění skriptu
     * se děje v samostatně session.
     * 
     * @param script cesta k příslušnému skriptu na koncovém systému.
     * @param scriptParams parametry (příkazy) předávané skriptu (CSV nebo jednoduché řetězce).
     * @return Výstup skriptu.
     * @throws ConnectorException
     */
    private String runCommand(String script, String scriptParams) throws ConnectorException {
    	String result = "";
    	ChannelExec channel = null;
    	ByteArrayOutputStream errorStream = null;
    	try {    		
    		
    		channel = (ChannelExec)connection.startConnection().openChannel("exec");
    		channel.setCommand(script);
    		
    		errorStream = new ByteArrayOutputStream();
            channel.setErrStream(errorStream);
            channel.setInputStream(null);
            channel.setOutputStream(null);

            channel.connect();          
            try {
                if (scriptParams != null && !scriptParams.equals("")) {
                    writeCommandToChannel(channel, scriptParams);
                }            	            	            	
                result = retrieveCommandResult(channel);                                                
            } catch (IOException ioExc) {
            	log.error("Error during retrieving command result. {0}",ioExc.getMessage());            
            } finally {
                channel.disconnect();
            }       
                        
            throwExceptionIfErrorOccured(channel, errorStream);
            
    	} catch (ConnectorException connExc) {
    		throw new ConnectorException(connExc.getMessage());
    	} catch (Exception ex) {
    		log.error("Eror during running command. {0}",ex.getMessage());
    	} finally {
    		//stop connection
    		dispose();
    	}        	    	    	    	
    	
    	return result;
    }    
    
    /**
     * Metoda slouží pro spouštění skriptů na koncovém systému. Skript je spuštěn v zadané session.
     * 
     * @param script cesta k příslušnému skriptu na koncovém systému.
     * @param scriptParams parametry (příkazy) předávané skriptu (CSV nebo jednoduché řetězce).
     * @param session session, ve které bude spuštěn skript.
     * @return Výstup skriptu.
     * @throws ConnectorException
     */
    private String runCommand(String script, String scriptParams, Session session) throws ConnectorException {
    	String result = "";
    	ChannelExec channel = null;
    	ByteArrayOutputStream errorStream = null;
    	try {    		
    		
    		channel = (ChannelExec)session.openChannel("exec");
    		channel.setCommand(script);
    		
    		errorStream = new ByteArrayOutputStream();
            channel.setErrStream(errorStream);
            channel.setInputStream(null);
            channel.setOutputStream(null);

            channel.connect();          
            try {
                if (scriptParams != null && !scriptParams.equals("")) {
                    writeCommandToChannel(channel, scriptParams);
                }            	            	            	
                result = retrieveCommandResult(channel);                                                
            } catch (IOException ioExc) {
            	log.error("Error during retrieving command result. {0}",ioExc.getMessage());            
            } finally {
                channel.disconnect();
            }       
                        
            throwExceptionIfErrorOccured(channel, errorStream);
            
    	} catch (ConnectorException connExc) {
    		throw new ConnectorException(connExc.getMessage());
    	} catch (Exception ex) {
    		log.error("Eror during running command. {0}",ex.getMessage());
    	}     	    	    	    	
    	
    	return result;
    }
    
    /**
     * Metoda pro zapsání příkazu do datového kanálu, ve kterém je přenášena na koncový systém.
     * 
     * @param channel
     * @param command přikaz, který se má provézt (ve formátu CSV).
     * @throws IOException
     */
    private void writeCommandToChannel(Channel channel, String command) throws IOException {
        OutputStream out = channel.getOutputStream();
        try {
            out.write(command.getBytes(ENCODING));
            out.flush();
        } catch (IOException ioExc) {
        	log.error(ioExc.getMessage());        
        } finally {
            out.close();
        }
        
    }
    
    /**
     * Metoda slouží pro konverzi dat ze vstupního proudu do Stringu.
     * 
     * @param is vstupní proud.
     * @return Řetezcová reprezentace dat ve vstupní proudu.
     * @throws IOException
     */
    private static String convertStreamToString(InputStream is) throws IOException {
        if (is != null) {
            StringBuilder sb = new StringBuilder();
            String line;

            BufferedReader reader = new BufferedReader(new InputStreamReader(is, ENCODING));
            while ((line = reader.readLine()) != null) {
                sb.append(line).append(System.getProperty("line.separator"));
            }

            return sb.toString();
        } else {
            return "";
        }
    }
    
    /**
     * Metoda pro získání výsledku prováděného příkazu na koncovém systému.
     * 
     * @param channel
     * @return Výstup prováděného příkazu.
     * @throws IOException
     */
    private String retrieveCommandResult(Channel channel) throws IOException {        
        channel.setInputStream(null);
        InputStream in = channel.getInputStream();

        String result = convertStreamToString(in);
        while (!channel.isClosed()) {
            try {
                Thread.sleep(50);
            } catch (Exception e) {
            }
            result += convertStreamToString(in);
        }
        
        return result;
    }
    
    /**
     * Metoda kontroluje, zda se příkaz na koncovém systému provedl správně (s návratovou
     * hodnotou 0). Pokud tomu tak nebylo, tak vyhodí výjimku obsahující chybovou zprávu
     * obdrženou od odpovídajícího skriptu.
     * 
     * @param channel
     * @param errorStream proud s chybovým výstupem od skriptu.
     * @throws ConnectorException
     */
    private void throwExceptionIfErrorOccured(Channel channel, ByteArrayOutputStream errorStream) throws ConnectorException {
        if (channel.getExitStatus() != 0) {
            String errMsg = String.format(
                    "Command returns status code '%d'. %s",
                    channel.getExitStatus(), errorStream.toString()
            );            
            log.error(errMsg);
            
            throw new ConnectorException(errMsg);
        }        
    }    
    
    /**
     * Metoda pro transformaci pole Stringů do podoby CSV textu.
     * 
     * @param data data v poli Stringů.
     * @return Retězec ve formátu CSV obsahující zadaná data.
     * @throws IOException
     */
    private String getCSVLineFromStrings(String [] data) throws IOException {        

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        CsvWriter writer = new CsvWriter(
                output, SSHConfiguration.DELIMITER, Charset.forName(ENCODING)
        );

        writer.setEscapeMode(getCsvReaderMode());
        writer.writeRecord(data, true);
        writer.flush();

        String result = removeEndLineChar(output.toString(ENCODING));
        
        return result;
    }
    
    /**
     * Metoda navrací kód vybrané metody "eskejpování" z konfigurace.
     * 
     * @return Kód "eskejpovací" metody pro CsvReader.
     */
    private int getCsvReaderMode() {
    	//Nacteme si z konfigu "escape mode".
        String valueFromConfig = config.getEscapeMode();
        
        if (SSHMessages.SSH_ESCAPE_MODE_DOUBLED.equals(valueFromConfig)) {
            
            return CsvReader.ESCAPE_MODE_DOUBLED;

        } else if (SSHMessages.SSH_ESCAPE_MODE_BACKSLASH.equals(valueFromConfig)) {

            return CsvReader.ESCAPE_MODE_BACKSLASH;

        } else {
        	
        	//Error
            return -1;           
        }
    }
    
    /**
     * Metoda pro odstranění oddělovače řádků na konci zadaného řetězce.
     * 
     * @param value řetězec.
     * @return Řetězec bez oddělovače na konci.
     */
    private String removeEndLineChar(String value) {
        if (value == null || value.length() < 1) {
            return value;
        }
        
        char last = value.charAt(value.length() - 1);

        if (last == '\r' || last == '\n') {
            value = removeLastChar(value);
            
            if (value.length() < 1) {
                return value;
            }

            last = value.charAt(value.length() - 1);
            if (last == '\r' || last == '\n') {
                value = removeLastChar(value);
            }
        }

        return value;
    }

    /**
     * Metoda odstraňující poslední znak zadaného řetězce.
     * 
     * @param value zadaný řetězec.
     * @return Řetězec bez posledního znaku.
     */
    private String removeLastChar(String value) {
    	if (value != null && value.length() >= 1) {
    		return value.substring(0, value.length() - 1);
    	} else {
    		return null;
    	}        
    }
    
    /**
     * Metoda odstraňující poslední znak z řetězce ve StringBuilderu.
     * 
     * @param sb řetězec ve StringBuilderu.
     * @return Řetězec ve StringBuilderu bez posledního znaku.
     */
    private StringBuffer removeLastChar(StringBuffer sb) {
    	if (sb != null && sb.length() >= 1) {
    		return sb.deleteCharAt(sb.length()-1);
    	} else {
    		return null;
    	}
    }
    
    /**
     * Metoda pro autentizaci uzivatele proti pripojenemu systemu.
     */
	public Uid authenticate(ObjectClass objClass, String accountId, GuardedString password,
			OperationOptions options) {
		String operationName = ""; 
    	String pathToScript = "";
    	StringBuffer userHeader = new StringBuffer();
        List<String> dataForUserLine = new ArrayList<String>();
        
    	if (objClass.is(ObjectClass.ACCOUNT_NAME)) {
    		operationName = SSHMessages.SSH_AUTHENTICATE;
    		pathToScript = config.getAuthenticate();
    		userHeader.append(SSHMessages.SSH_HEADER_ACCOUNTID);
    		userHeader.append(SSHConfiguration.DELIMITER);
    		userHeader.append(SSHMessages.SSH_HEADER_PASSWORD);
    		checkPathToScript(pathToScript, operationName);
        	
        	dataForUserLine.add(accountId);
        	dataForUserLine.add(SSHConnection.asString(password));
        	String scriptParams = createCommandCSV(operationName, userHeader, dataForUserLine);		    	
        	String result = runCommand(pathToScript, scriptParams);
    		if ((result == null) || (StringUtil.isBlank(result))) {
    			return null;
    		}
    		return new Uid(result.trim());
    	
    	//Autentizace je pouze pro uzivatele
    	} else {
    		return null;
    	}    	
    	
	}

	/** Metoda pro spuštění skriptu na koncovém systému.
	 * @param context obsahuje kontext spouštěného skriptu. V atributu language očekává "sh", 
	 * v atributu text očekává cestu k příslušnému skriptu na koncovém systému,
	 * v atributu arguments jsou parametry, které dostane skript na vstupu.
	 */
	public Object runScriptOnResource(ScriptContext context, OperationOptions options) {
		String scriptLang = context.getScriptLanguage();
		String scriptText = context.getScriptText();
		Map<String, Object> args = context.getScriptArguments();
		
		List<String> dataForUserLine = new ArrayList<String>();
        StringBuffer userHeader = new StringBuffer();
        for (String arg : args.keySet()) {
			Object value = args.get(arg);
			String valueAsString = "";
			if (value instanceof GuardedString) {
				valueAsString = SSHConnection.asString(value);
			} else if (value != null) {
				valueAsString = value.toString();
			}
			userHeader.append(arg);
    		userHeader.append(SSHConfiguration.DELIMITER);
    		dataForUserLine.add(valueAsString);
		}
		
        removeLastChar(userHeader);
        
		String result = null;
		if ("sh".equalsIgnoreCase(scriptLang)) {
			String scriptParams = createCommandCSV("runScript", userHeader, dataForUserLine);
			
			result = runCommand(scriptText, scriptParams);
		} else {
			throw new ConnectorException("Unsupported script language: " + scriptLang + ". Available languages: sh");
		}
		
		return result;
	}

}


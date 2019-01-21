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

package eu.bcvsolutions.idm.connector.ssh.filters;

import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import eu.bcvsolutions.idm.connector.ssh.SSHMessages;

/**
 * Třída sloužící k vytváření vyhledávacích filtrů pro uživatelské účty.
 * 
 * @author Jaromír Mlejnek
 */
public class SSHUserFilterTranslator extends AbstractFilterTranslator<String> {	
	
	/**
	 * Metoda vytvoří dotaz (ve formě atributů pro příslušný skript koncového systému) 
	 * pro vyhledání uživatelského účtu dle specifikovaného uživatelského jména (prozatím). 
	 * Uživatelské jméno (instance třídy Name nebo Uid) je uloženo jako atribut v objektu 
	 * <b>filter</b>.	
	 */
	@Override
	protected String createEqualsExpression(EqualsFilter filter, boolean not) {		
		if (not) {
			throw new UnsupportedOperationException("Not supported yet.");
		}
		
		String username = "";
		Attribute attrib = filter.getAttribute();
		
		if (attrib == null) {
			return null;
		}
		
		if (attrib.is(Name.NAME)) {
			username = ((Name)attrib).getNameValue();
		} else if (attrib.is(Uid.NAME)) {
			username = ((Uid)attrib).getUidValue();
		} else if (attrib.getValue() != null) {
			username = (String)attrib.getValue().get(0);
		}		
		
		String operationName = SSHMessages.SSH_GETUSER;     	
		//TODO Opet pevna hodnota.
		String header = SSHMessages.SSH_HEADER_ACCOUNTID;         
	            
	    String scriptParams = String.format("%s\n%s\n%s\n", operationName, header, username);
	    
		return scriptParams;
	}
	
}

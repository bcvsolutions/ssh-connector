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

/**
 * Deklarované konstanty.
 * 
 * @author Jaromír Mlejnek
 */
public interface SSHMessages {
	
    public static final String SSH_GETUSER = "getUser";
    public static final String SSH_CREATEUSER = "createUser";
    public static final String SSH_DELETEUSER = "deleteUser";
    public static final String SSH_ENABLEUSER = "enableUser";
    public static final String SSH_DISABLEUSER = "disableUser";
    public static final String SSH_UPDATEUSER = "updateUser";
    public static final String SSH_AUTHENTICATE = "authenticate";
    
    public static final String SSH_GETGROUP = "getGroup";
    public static final String SSH_CREATEGROUP = "createGroup";
    public static final String SSH_DELETEGROUP = "deleteGroup";
    public static final String SSH_UPDATEGROUP = "updateGroup";

    public static final String SSH_LISTOBJECTS = "listObjects";
    public static final String SSH_ATTRIBUTESLIST = "getAttributesSchema";

    public static final String SSH_HEADER_ACCOUNTID = "AccountId";
    public static final String SSH_HEADER_NEW_ACCOUNTID = "newAccountId";
    public static final String SSH_HEADER_PASSWORD = "password";
    public static final String SSH_HEADER_UID = "UID";
    public static final String SSH_HEADER_GID = "GID";
    public static final String SSH_HEADER_GECOS = "GECOS";
    public static final String SSH_HEADER_HOMEDIRECTORY = "HomeDirectory";
    public static final String SSH_HEADER_SHELL = "Shell";
    public static final String SSH_HEADER_GROUPS = "Groups";    
    public static final String SSH_HEADER_STATUS = "Status";
    
    public static final String SSH_HEADER_GROUP_NAME = "groupName";
    public static final String SSH_HEADER_USERS = "Users";
    
    public static final String SSH_OBJECT_TYPE_GROUP = "Group";
    public static final String SSH_STATUS_LOCK = "LOCK";
    public static final String SSH_STATUS_UNLOCK = "UNLOCK";
    
    public static final String SSH_HEADER_OBJECTTYPE = "objectType";
    
    public static final String SSH_ESCAPE_MODE_DOUBLED = "DOUBLED";
    public static final String SSH_ESCAPE_MODE_BACKSLASH = "BACKSLASH";
       
    public static final String SSH_ATTRIBUTE_NAME = "Attribute_Name";
    public static final String SSH_ATTRIBUTE_TYPE = "Type";
    public static final String SSH_ATTRIBUTE_FLAGS = "Flags";

}

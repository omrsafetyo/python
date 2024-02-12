import ldap3
import logging
import json
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups
from ldap3.extend.microsoft.removeMembersFromGroups import ad_remove_members_from_groups
from ldap3.extend.microsoft.unlockAccount import ad_unlock_account
from ldap3.extend.microsoft.modifyPassword import ad_modify_password
# from ldap3 import Server, Connection, LDIF, SIMPLE, SYNC, ALL, SASL, SAFE_RESTARTABLE, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import safe_rdn
import re

log = logging.getLogger()
log.setLevel(logging.INFO)

class LdapHelper:
    """
    A Helper Class to interact with Active Directory via Ldap
    """
    
    def __init__(self):
        """
        An object to interact with Active Directory via Ldap
        """
        self.connection = ""
        self.domain_name = ""
        self.domain_controller = ""
        self.root_dn = ""
        self.dsa_info = ""
        self.connected = False
        self.use_ssl = False
        
    def __repr__(self):
        return f"LdapHelper(domain_name={self.domain_name}, root_dn={self.root_dn}, connected={self.connected})"

    def __str__(self):
        return f"LdapHelper: Domain={self.domain_name}, Root DN={self.root_dn}, Connected={self.connected}"

    ### INTERACT WITH THE SELF OBJECT ###
    
    def is_connected(self):
        """
        Checks if the Ldap connection is open and connected

        Parameters: none

        Returns: 
        - boolean: True if connected, False if not connected
        """
        if self.connected == False:
            return False

        if self.connection.closed:
            self.connected = False
            return False
        
        if not self.connection.bind():
            log.info('error in bind' + self.connection.result)
            self.connected = False
            return False
        
        return True

    def set_domain(self, domain_name):
        """
        Sets the domain_name property of the object

        Parameters: 
        - domain_name (string)

        Returns: none
        """
        self.domain_name = domain_name
    
    def set_root_dn(self, dn):
        """
        Sets the root_dn property of the object

        Parameters: dn - the root_dn for all search operations

        Returns: none
        """
        self.root_dn = dn

    def get_domain(self):
        """
        Returns the domain name of the connected Ldap server

        Parameters: none

        Returns: 
        - string: the name of the connected domain
        """
        return self.domain_name

    def get_server_info(self, domain_controller:str):
        if self.is_connected():
            dsa_info = json.loads(self.connection.server.info.to_json()).get('raw', None)
        else:
            # connect insecurely and anonymously to try to get info
            server = ldap3.Server(domain_controller, get_info="ALL")
            try:
                conn = ldap3.Connection(server, auto_bind=True)
                dsa_info = json.loads(conn.server.info.to_json()).get('raw', None)
            except Exception as e:
                log.info("Unable to get server info")
                log.info(e)
        return dsa_info
        
    def connect_ldap(self, domain_controller: str, auth_username: str, auth_password: str, authentication_method = ldap3.NTLM, force_connection: bool = False):
        """
        Creates a new connection to the Ldap server

        Parameters:
        - domain_controller (string): the fqdn of the Domain Controller.  Must match the certificate name of the server for SSL
        - auth_username (string): Username for connection
        - auth_password (string): Password for authentication
        - authentication_method (ldap3.AccessMethod): Uses NTLM for Active Directory
        - force_connection (bool): Pass as True to force re-creating the connection if already connected.
            Would be used for changing the connected server, or authentication credentials.
            If not True, this will return True if the server is already connected

        Returns: 
        - boolean: True if connection is successful, False if connection fails

        Example:
        >>> ldap = LdapHelper()
        >>> ldap.connect_ldap(domain_controller=domainController, auth_username=authData["username"], auth_password=authData["password"])
        """
        if self.is_connected() and force_connection == False:
            return True

        self.domain_controller = domain_controller
        if authentication_method != ldap3.NTLM:
            username = self.convert_auth_username_for_kerberos(auth_username)
        else:
            username = auth_username
            
        if not username:
            username = auth_username
        log.info(f"Connecting to {domain_controller} with {username}")
        
        if self.use_ssl:
            server = ldap3.Server(domain_controller, 
                            get_info="ALL",
                            port=636,
                            use_ssl=True
                        )
            conn = ldap3.Connection(server,
                            username, 
                            auth_password, 
                            authentication = authentication_method,
                            auto_bind=True,
                        )
        else:
            server = ldap3.Server(domain_controller,
                            get_info="ALL",
                            port=389,
                            use_ssl=False
                        )
            conn = ldap3.Connection(server, 
                            auth_username,
                            auth_password,
                            authentication = authentication_method,
                            auto_bind=True
                        )
        try:
            if not conn.bind():
                log.info('error in bind')
                log.info(conn.result)
                return False
        except Exception as e:
            log.info('error in bind')
            log.info(conn.result)
            log.error(e)
            return False
        log.info("Connected")
        log.info(conn)
        
        self.connection = conn
        self.connected = True

        # dsa_info = json.loads(server.info.to_json()).get('raw', None)
        dsa_info = self.get_server_info(domain_controller=domain_controller)
        domain_name = dsa_info["ldapServiceName"][0].split(":")[0]
        self.set_domain(domain_name)
        self.set_root_dn(dsa_info["rootDomainNamingContext"][0])
        self.dsa_info = dsa_info
        return True

    def disconnect(self):
        if self.is_connected():
            self.connection.unbind()

    
    ### GROUP OPERATIONS ###
    
    def find_group(self, group_name: str, *args, **kwargs):
        """
        Crafts a group specific search string based on the passed group name and runs the search method
        
        Parameters:
        - group_name (string): the Name of the group
        - base_ou (string - optional): The base_ou to use for the search

        Returns: 
        - object: Unpacked search result for the group search

        Example:
        >>> group = ldap.find_ou(group_name="Domain Users")
        """
        base_ou = kwargs.get('base_ou', None)
        
        if not base_ou:
            base_ou = self.root_dn

        search_filter = self.create_safe_basic_search_string_from_objectclass_fieldname_value(object_class="group", search_field="sAMAccountName", search_value=group_name)
        group = self.search(search_filter, base_ou)
        
        group_result = self.unpack_search_result(group)
        if not group_result:
            log.error(f"Unable to find user {group_name} in {base_ou}")
            
        return group_result
        
    def get_groups_under_ou(self, parent_ou_dn: str, *args, **kwargs):
        """
        Enumerates all groups under a specified OU
        
        Parameters:
        - parent_ou_dn (string): The dn of the OU to get groups under

        Returns: 
        - object: Unpacked search result for the group search

        Example:
        >>> ous = ldap.get_groups_under_ou(parent_ou_dn="OU=Groups,OU=Accounts,DC=acme,DC=com)
        """
        search_filter = '(objectclass=group)'
        groups = self.search(search_filter, parent_ou_dn)
        
        groups_result = self.unpack_search_result(groups)
        if not groups_result:
            log.error(f"Unable to find groups under {parent_ou_dn}")
            
        return groups_result
        
    def create_group(self, group_name: str, parent_ou_dn: str, *args, **kwargs):
        """
        Creates agroup
        
        Parameters:
        - group_name (string): the group name to use for group creation
        - parent_ou_dn (string): DN of the OU to put the group in

        Returns: 
        - object: the group object created

        Example:
        >>> target_ou_dn = "OU=Groups,OU=Accounts,DC=acme,DC=com"
        >>> ldap.create_group(group_name="My Group", ou_dn=target_ou_dn, description="Group for new users")
        """
        attribute_dictionary = {
            "cn" : group_name,
            "sAMAccountName" : group_name
        }

        object_class = kwargs.get("object_class", "group") # see if this was passed, if not default to group
        
        valid_classes = ["group"]
        if object_class not in valid_classes:
            object_class = "group"
            
        group_dn = f"cn={group_name},{parent_ou_dn}"
        result = self.connection.add(group_dn, object_class, attribute_dictionary)
        return result
        
    ### OU OPERATIONS ###
    
    def find_ou(self, ou_name: str, *args, **kwargs):
        """
        Crafts an Organizational Unit specific search string based on the passed ou name and runs the search method
        
        Parameters:
        - ou_name (string): the Name of the Organizational Unit
        - base_ou (string - optional): The base_ou to use for the search

        Returns: 
        - object: Unpacked search result for the ou search

        Example:
        >>> ou = ldap.find_ou(group_name="Users")
        """
        base_ou = kwargs.get('base_ou', None)
        
        if not base_ou:
            base_ou = self.root_dn
            
        search_filter = self.create_safe_basic_search_string_from_objectclass_fieldname_value(object_class="ou", search_field="Name", search_value=ou_name)
        ou = self.search(search_filter, base_ou)
        
        ou_result = self.unpack_search_result(ou)
        if not ou_result:
            log.error(f"Unable to find user {ou_name} in {base_ou}")
            
        return ou_result
        
    def get_child_ous(self, parent_ou_dn: str, *args, **kwargs):
        """
        Enumerates all child OUs under a specified parent
        
        Parameters:
        - parent_ou_dn (string): The dn of the OU to get children for

        Returns: 
        - object: Unpacked search result for the ou search

        Example:
        >>> ous = ldap.get_child_ous(parent_ou_dn="Users")
        """
        search_filter = '(objectclass=organizationalUnit)'
        ous = self.search(search_filter, parent_ou_dn)
        
        ous_result = self.unpack_search_result(ous)
        if not ous_result:
            log.error(f"Unable to find OUs under {parent_ou_dn}")
            
        return ous_result
    
    def create_ou(self, ou_name: str, parent_ou_dn: str, *args, **kwargs):
        """
        Creates an OU
        
        Parameters:
        - ou_name (string): the name to use for OU creation
        - parent_ou_dn (string): DN of the OU to put the OU in

        Returns: 
        - object: the OU object created

        Example:
        >>> target_ou_dn = "OU=Groups,OU=Accounts,DC=acme,DC=com"
        >>> ldap.create_ou(ou_name="My_Sub_OU", ou_dn=target_ou_dn)
        """
        object_class = kwargs.get("object_class", "organizationalUnit") # see if this was passed, if not default to organizationalUnit
        
        valid_classes = ["organizationalUnit"]
        if object_class not in valid_classes:
            object_class = "organizationalUnit"
            
        ou_dn = f"OU={ou_name},{parent_ou_dn}"
        result = self.connection.add(ou_dn, object_class)
        return result
    
    ### USER OPERATIONS ###
    
    def find_user(self, username: str, *args, **kwargs):
        """
        Crafts a user specific search string based on the passed username and runs the search method
        
        Parameters:
        - username (string): the SamAccountName of the user
        - base_ou (string - optional): The base_ou to use for the search

        Returns: 
        - object: Unpacked search result for the user search

        Example:
        >>> user = ldap.find_user(user_name="brad.pitt")
        """
        base_ou = kwargs.get('base_ou', None)
        if not base_ou:
            base_ou = self.root_dn

        search_filter = self.create_safe_basic_search_string_from_objectclass_fieldname_value(object_class="user", search_field="sAMAccountName", search_value=username)
        user = self.search(search_filter, base_ou)
        user_result = self.unpack_search_result(user)
        
        if not user_result:
            log.error(f"Unable to find user {username} in {base_ou}")
            
        return user_result

    def get_user_by_dn(self, user_dn, *args, **kwargs):
        """
        Does a fine-grained search for a user based on the DN.
        This still uses the search function, but breaks the DN into the SamAccountName and the parent OU DN
         and prohibits the search to the containing OU to make the search faster.  This should be used if you
         already know the user DN
        
        Parameters:
        - user_dn (string): Full Dn of the user

        Returns: 
        - object: Unpacked search result for the user search

        Example:
        >>> user = ldap.get_user_by_dn(user_dn="CN=brad.pitt,OU=Users,OU=Accounts,DC=acme,DC=com")
        """
        if not self.is_valid_ldap_dn(user_dn):
            raise ValueError("Invalid Distinguished Name (dn) format.")
        user_split = user_dn.split(",", 1)
        user_name = user_split[0].split("=")[1]
        user_ou = user_split[1]
        log.info(f"looking for {user_name} in {user_ou}")
        user = self.find_user(username=user_name, base_ou=user_ou)
        return user

    def add_user_to_group(self, user_dn, group_dn):
        """
        Adds a user(s) to a specified group(s)
        
        Parameters:
        - user_dn (list string): the DN of the user or users to add.  Pass a list to do multiple users at once, or a string for just one.
        - group_dn (list string): the DN of the group to add users to. Pass a list for multiple groups at once, or a string for just one.

        Returns: 
        - boolean: True if added, False if not

        Example:
        >>> group = ldap.find_group(group_name="Domain Admins")
        >>> user = ldap.find_user(user_name="brad.pitt")
        >>> ldap.add_user_to_group(user_dn=user['dn'], group_dn=group['dn'])
        """
        if ad_add_members_to_groups(connection=self.connection, members_dn=user_dn, groups_dn=group_dn, fix=True):
            return True
        else:
            log.error(f"Error occurred adding {user_dn} to {group_dn}")
            return False

    def remove_user_from_group(self, user_dn, group_dn):
        """
        Removes a user(s) from specified group(s)
        
        Parameters:
        - user_dn (list string): the DN of the user or users to remove.  Pass a list to do multiple users at once, or a string for just one.
        - group_dn (list string): the DN of the group to remove users from. Pass a list for multiple groups at once, or a string for just one.

        Returns: 
        - boolean: True if removed, False if not

        Example:
        >>> group = ldap.find_group(group_name="Domain Admins")
        >>> user = ldap.find_user(user_name="brad.pitt")
        >>> ldap.remove_user_from_group(user_dn=user['dn'], group_dn=group['dn'])
        """       
        if ad_remove_members_from_groups(connection=self.connection, members_dn=user_dn, groups_dn=group_dn, fix=True):
            return True
        else:
            log.error(f"Error occurred removing {user_dn} from {group_dn}")
            return False
        
    def create_user(self, username: str, password:str, ou_dn:str, *args, **kwargs):
        """
        Creates a user
        
        Parameters:
        - username (string): the username to use for user creation
        - password (string): the password to set the user to
        - ou_dn (string): DN of the OU to put the user in

        Optional Parameters:
        - givenName (string): The given/first name of the user
        - sn (string): the surname/last name of the user
        - Department (string): The department the user belongs to
        - Description (string): A description for the user
        - displayName (string): Usually the full name, <FirstName LastName>
        - mail (string): The email address of the user
        - manager (string): The DN of the manager
        - name (string): Usually the full name, <FirstName LastName>
        - title (string): The Job Title of the user
        - object_class: The object type to create.  Can be "user" or "organizationalPerson". Default value is "user"

        Returns: 
        - object: the user object created

        Example:
        >>> target_ou_dn = "OU=Users,OU=Accounts,DC=acme,DC=com"
        >>> ldap.create_user(username="test_user", password=generated_password, ou_dn=target_ou_dn, mail="nathan.kulas.test@tylertech.com")
        """
        # conn.add('cn=b.young,ou=ldap3-tutorial,dc=demo1,dc=freeipa,dc=org', 'inetOrgPerson', {'givenName': 'Beatrix', 'sn': 'Young', 'departmentNumber': 'DEV', 'telephoneNumber': 1111})
        # https://ldap3.readthedocs.io/en/latest/tutorial_operations.html#create-an-entry
        attribute_dictionary = {
            #"userPassword" : password,  # may or may not work... only works via LDAPS if at all
            "sAMAccountName" : username,
            "unicodePwd" : '"{}"'.format(password).encode('utf-16-le')
        }
        
        accepted_params = [
            "givenName",
            "sn",
            "cn",
            "Department",
            "Description",
            "displayName",
            "mail",
            "manager",
            "name",
            "title",
            "userAccountControl"
            "accountExpires"
            ]
        
        mapping_params = {
            "displayName" : "name",
            "name" : "displayName"
        }
        
        # Default to a regular user
        if "userAccountControl" not in kwargs:
            attribute_dictionary["userAccountControl"] = 512
            
        # Don't expire the acount by default
        if "accountExpires" not in kwargs:
            attribute_dictionary["accountExpires"] = 0

        for arg in kwargs:
            if arg in accepted_params:
                if arg == 'email' and not self.is_valid_email(kwargs[arg]):
                    continue
                attribute_dictionary[arg] = kwargs[arg]

            # Some fields get the same values.  If one of the mapping keys is passed
            # but the mapped field isn't passed, also add that
            if arg in accepted_params and arg in mapping_params:
                value = mapping_params[arg]
                if value not in kwargs:
                    attribute_dictionary[value] = kwargs[arg]

        object_class = kwargs.get("object_class", "user") # see if this was passed, if not default to user
        
        valid_classes = ["user", "organizationalPerson"]
        if object_class not in valid_classes:
            object_class = "user"
            
        user_dn = f"cn={username},{ou_dn}"
        result = self.connection.add(user_dn, object_class, attribute_dictionary)
        log.info(result)
        #pw_set_result = self.set_user_password(user_dn, password)
        #log.info(pw_set_result)
        #enable_result = self.enable_user(user_dn)
        # log.info(enable_result)
        return result
    
    def destroy_user(self, user_dn, *args, **kwargs):
        """
        Deletes a user from the directory
        
        Parameters:
        - user_dn (list string): the DN of the user to remove.

        Returns: 
        - boolean: True if removed, False if not

        Example:
        >>> user = ldap.find_user(user_name="brad.pitt")
        >>> ldap.destroy_user(user_dn=user['dn'])        
        """
        if not self.is_valid_ldap_dn(user_dn):
            return False

        user = self.get_user_by_dn(user_dn)
        if user:
            self.connection.delete(user_dn)
            log.info(self.connection.result)
            return self.connection.result
        else:
            log.info(f"{user_dn} not found or not a user")
            return False

    def move_user(self, user_dn, target_ou_dn):
        """
        Moves a user to the target OU
        
        Parameters:
        - user_dn (string): the DN of the user to move.
        - target_ou_dn (string): the target OU to move the user to

        Returns: 
        - Result:  Result information from the Ldap connection operation

        Example:
        >>> user = ldap.find_user(user_name="brad.pitt")
        >>> target_ou_dn = "OU=Users,OU=Accounts,DC=acme,DC=com"
        >>> result = ldap.move_user(user['dn'], target_ou_dn)
        """
        log.info(f"Moving user {user_dn} to {target_ou_dn}")
        user_cn = safe_rdn(user_dn)[0]
        self.connection.modify_dn(user_dn, user_cn, new_superior=target_ou_dn)
        log.info(self.connection.result)
        return self.connection.result
        
    def unlock_account(self, user_dn):
        """
        Unlocks a user's account
        
        Parameters:
        - user_dn (string): the DN of the user to move.
        - target_ou_dn (string): the target OU to move the user to

        Returns: 
        - Boolean or Result:  Result information from the Ldap connection operation, or False if an invalid Dn is passed

        Example:
        >>> user = ldap.find_user(user_name="brad.pitt")
        >>> ldap.unlock_account(user['dn'])
        """
        # https://github.com/cannatag/ldap3/blob/dev/ldap3/extend/microsoft/unlockAccount.py
        if self.is_valid_ldap_dn(user_dn):
            ad_unlock_account(connection=self.connection, user_dn=user_dn)
            log.info(self.connection.result)
            return self.connection.result
        else:
            log.info(f"Invalid user DN passed: {user_dn}")
            return False

    def set_user_password(self, user_dn, new_password, old_password=None):
        """
        Sets a password
        
        Parameters:
        - user_dn (string): the DN of the user to change
        - new_password (string): the new password to set
        - old_password (string): the existing password, or None if you want to set using admin privileges.
            note: always provide the old_password if possible.  Otherwise password policies are bypassed.
            By passing the old_password you allow all checks and balances from AD to be enforced.

        Returns: 
        - Result:  Result information from the Ldap connection operation

        Example:
        >>> import uuid
        >>> temp_password = str(uuid.uuid4())
        >>> generated_password = str(uuid.uuid4())
        >>> user = ldap.find_user(user_name="brad.pitt")
        >>> if ldap.set_user_password(user_dn, new_password=temp_password, old_password=None):
        >>>   log.info(ldap.connection.result)
        >>>   result = ldap.set_user_password(user_dn, new_password=generated_password, old_password=temp_password)
        >>>   log.info(result)
        >>> else:
        >>>   log.info(ldap.connection.result)
        """
        # https://github.com/cannatag/ldap3/blob/dev/ldap3/extend/microsoft/modifyPassword.py
        # https://ldap3.readthedocs.io/en/latest/microsoft.html
        result = ad_modify_password(connection=self.connection, user_dn=user_dn, new_password=new_password, old_password=old_password)
        return result
    
    def get_members_of_group(self, group_dn, *args, **kwargs):
        """
        Gets all the members of a specified AD Group
        
        Parameters:
        - group_dn (string): the DN of the user to change
        - base_ou (string - optional) - This is a bit misleading, but this filters users that are returned.
          Rather than getting the group and enumerating group membership, this function uses the search feature
          to search for users starting in the base_ou where the groupmembership includes the specified group DN
          Only use this if you want to limit the search results of the user to a given OU

        Returns: 
        - Result:  Result information from the Ldap connection operation

        Example:
        >>> group = ldap.find_group(group_name="Domain Admins")
        >>> members = ldap.get_members_of_group(group_dn=group['dn'])
        >>> for user in members:
        >>>   log.info(user['dn'])
        """
        if not self.is_valid_ldap_dn(group_dn):
            log.info(f"Provided DN is not a valid dn: {group_dn}")
            return False

        base_ou = kwargs.get('base_ou', None)
        if not base_ou or (base_ou and not self.is_valid_ldap_dn(base_ou)):
            # base_ou = "DC={}".format(",DC=".join(self.domain_name.split('.')))
            base_ou = self.root_dn
            
        # https://confluence.atlassian.com/kb/how-to-write-ldap-search-filters-792496933.html
        # (&(objectCategory=user)(sAMAccountName=*)(|(memberOf=CN=Jira Administrators,CN=Users,DC=test,DC=mydomain,DC=com)(memberOf=CN=jira-users,CN=Users,DC=test,DC=mydomain,DC=com)(memberOf=CN=confluence-administrators,CN=Users,DC=test,DC=mydomain,DC=com)))
        search_filter = f'(&(objectCategory=user)(sAMAccountName=*)(memberOf={group_dn}))'
        users = self.search(search_filter, base_ou)
        
        users_result = self.unpack_search_result(users)
        if not users_result:
            log.error(f"Unable to find group {group_dn} in {base_ou}")
            
        return users_result
    
    def set_uac(self, user_dn:str , uac: int):
        """
        Sets the userAccountControl attribute of a user.  Validates the user exists.
        
        Parameters:
        - user_dn (string): the DN of the user to modify.
        - uac (int): value of the uac field
          https://learn.microsoft.com/en-GB/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties

        Returns: 
        - Boolean or Result:  Result information from the Ldap connection operation, or False if an invalid user is passed

        Example: (user not found)
        >>> ldap.set_uac(user_dn="CN=brad.pitt,OU=Users,OU=Accounts,DC=acme,DC=com")
        >>> False
        
        Example: (user not found)
        >>> ldap.set_uac(user_dn="CN=brad.pitt,OU=Users,OU=Accounts,DC=acme,DC=com")
        >>> 
        """
        user = self.get_user_by_dn(user_dn)
        if user:
            self.connection.modify(user_dn, {'userAccountControl': [('MODIFY_REPLACE', uac)]})
            return self.connection.result
        else:
            log.info(f"{user_dn} not found or not a user")
            return False
    
    def enable_user(self, user_dn: str, set_pw_not_expire: bool = False):
        """
        Enables a user
        
        Parameters:
        - user_dn (string): the DN of the user to enable.
        - set_pw_not_expire (bool): whether the password should be set to not expire

        Returns: 
        - Boolean or Result:  Result information from the Ldap MODIFY_REPLACE operation, or False if an invalid user is passed

        Example: (user not found)
        >>> ldap.enable_user(user_dn="CN=brad.pitt,OU=Users,OU=Accounts,DC=acme,DC=com")
        >>> False
        
        Example: (user found)
        >>> ldap.enable_user(user_dn="CN=brad.pitt,OU=Users,OU=Accounts,DC=acme,DC=com")
        >>> 
        """
        NORMAL_ACCOUNT=512
        DONT_EXPIRE_PASSWORD=65536
        
        uac = NORMAL_ACCOUNT
        if set_pw_not_expire:
            uac += DONT_EXPIRE_PASSWORD
            
        return self.set_uac(user_dn, uac)

    def disable_user(self, user_dn):
        """
        Disables a user
        
        Parameters:
        - user_dn (string): the DN of the user to disable.
        - set_pw_not_expire (bool): whether the password should be set to not expire

        Returns: 
        - Boolean or Result:  Result information from the Ldap MODIFY_REPLACE operation, or False if an invalid user is passed

        Example: (user not found)
        >>> ldap.enable_user(user_dn="CN=brad.pitt,OU=Users,OU=Accounts,DC=acme,DC=com")
        >>> False
        
        Example: (user found)
        >>> ldap.enable_user(user_dn="CN=brad.pitt,OU=Users,OU=Accounts,DC=acme,DC=com")
        >>> 
        """
        ACCOUNT_DISABLE=2
        uac = ACCOUNT_DISABLE
        return self.set_uac(user_dn, uac)
    
    ### HELPER FUNCTIONS ###
    
    def create_safe_basic_search_string_from_objectclass_fieldname_value(self, object_class, search_field, search_value):
        """
        Helper to create a basic but safe search string.
        '(&(objectclass={sanitized_class})({sanitized_field}={sanitized_value}))'
        Uses the built-in escape_filter_chars method to ensure that the search string is sanitized and safe,
         to prevent injection attacks
        https://www.linkedin.com/pulse/ldap-injection-django-jerin-jose/

        Parameters:
        - object_class (string): the Ldap object class to return
        - search_field (string): The field to filter on
        - search_value (string): The value to filter for the specified field

        Returns: 
        - string: The santizied ldap search string in string format

        Example:
        >>> user = ldap.create_safe_basic_search_string_from_objectclass_fieldname_value(object_class="user", search_field="SamAccountName", search_value="brad.pitt")
        '(&(objectclass=user)(SamAccountName=brad.pitt))'
        """
        sanitized_class =  escape_filter_chars(object_class)
        sanitized_field =  escape_filter_chars(search_field)
        sanitized_value =  escape_filter_chars(search_value)
        search_filter = f'(&(objectclass={sanitized_class})({sanitized_field}={sanitized_value}))'
        log.info(search_filter)
        return search_filter

    def search(self, search_filter: str, base_ou: str):
        """
        Searches the LDAP directory using the specified search filter and base_ou

        Parameters:
        - search_filter (string): LDAP search string.  See documentation
        - base_ou (string): The DN of the base_ou for the search

        Returns: 
        - boolean: False if there is no search result
        - object: a search object result from ldap3
        """
        if self.connection.search(base_ou, search_filter, attributes=[ldap3.ALL_ATTRIBUTES, ldap3.ALL_OPERATIONAL_ATTRIBUTES]):
            try:
                object = json.loads(self.connection.response_to_json())
            except:
                object = self.connection.response[0]

            return object
        else:
            return False
    
    def unpack_search_result(self, result):
        """
        Unpacks a search result.  The search result returns an object with an 'entries' list.
        Instead of returning this base object, we unpack the entries list, returning False if the list is empty,
            the only item in the list if the length is 1,
            or the list itself if len > 1

        Parameters:
        - result (object): the result of the search 

        Returns: 
        - boolean: False if entries length is 0
        - object: A single item if the length is 1
        - list[objects]: a list of objects if length > 1
        """
        if not result or len(result['entries']) == 0:
            return False
            
        if len(result['entries']) == 1:
            return result['entries'][0]
            
        return result['entries']

    def is_valid_email(self, email: str):
        """
        Check if a string is a valid email address

        Parameters:
        - email (str): The string to be validated.

        Returns:
        - bool: True if the input is a valid email, False otherwise.

        Example:
        >>> is_valid_email("nathan.kulas@tylertech.com")
        True
        >>> is_valid_email("thisaddress@noparentdomain")
        False
        """
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValueError("Invalid email address.")
        return True

    def is_valid_ldap_dn(self, dn: str):
        """
        Check if a string is a valid LDAP Distinguished Name (DN).

        Parameters:
        - dn (str): The string to be validated.

        Returns:
        - bool: True if the input is a valid LDAP DN, False otherwise.

        Example:
        >>> is_valid_ldap_dn("cn=user,ou=people,dc=example,dc=com")
        True 
        >>> is_valid_ldap_dn("invalid_dn")
        False
        """

        # Define a regular expression pattern for LDAP DNs
        ldap_dn_pattern = re.compile(
            r"^(?:(?:[A-Za-z0-9]+=[^,]+),?)+$"
        )

        # Check if the provided string matches the LDAP DN pattern
        return bool(re.match(ldap_dn_pattern, dn))
            
    def convert_auth_username_for_kerberos(self, username:str):
        """
        Converts a supplied username in domain.com/username format to username@domain.com format
    
        Parameters:
        - username (str): The username, expecting domain.com/user format
    
        Returns:
        - string: username in user@domain.com format
    
        Example:
        >>> convert_auth_username_for_kerberos("domain.com/brad.pitt")
        brad.pitt@domain.com
        >>> convert_auth_username_for_kerberos("brad.pitt@domain.com")
        brad.pitt@domain.com
        """
        # Define a regular expression pattern for User Principal Name format e.g. username@domain.com
        kerberos_pattern = re.compile(r"[^@]+@[^@]+\.[^@]+")
    
        # Check if the provided string matches the pattern already, if so, just return the username
        if bool(re.match(kerberos_pattern, username)):
            return username
        
        # Define a regular expression pattern for Down-Level Logon Name format e.g. domain.com\username
        ntlm_pattern = re.compile(r"(?P<domain>[^\\@]+\.[^\\@]+)[\\/](?P<username>[^\\@]+)")
        match = re.match(ntlm_pattern, username)
        if match:
            return "{}@{}".format(match.group('username'), match.group('domain'))
    
        # Catch all.. return no username because we could not convert to kerberos format
        log.info(f"Unsupported format: {username}")
        return None

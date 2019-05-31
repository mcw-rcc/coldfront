import json
import logging

import ldap.filter
from coldfront.core.user.utils import UserSearch
from coldfront.core.utils.common import import_from_settings
import ldap

logger = logging.getLogger(__name__)

class LDAPUserSearch(UserSearch):
    search_source = 'LDAP'

    def __init__(self, user_search_string, search_by):
        super().__init__(user_search_string, search_by)
        self.LDAP_SERVER_URI = import_from_settings('AUTH_LDAP_SERVER_URI')
        self.LDAP_USER_SEARCH_BASE = import_from_settings('AUTH_LDAP_USER_SEARCH_BASE')
        self.LDAP_BIND_DN = import_from_settings('AUTH_LDAP_BIND_DN', None)
        self.LDAP_BIND_PASSWORD = import_from_settings('AUTH_LDAP_BIND_PASSWORD', None)

        self.conn = ldap.initialize(self.LDAP_SERVER_URI)
        # Required for our LDAP
        self.conn.start_tls_s()
        self.conn.simple_bind_s(self.LDAP_BIND_DN, self.LDAP_BIND_PASSWORD)

    def parse_ldap_entry(self, entry):
        mail = result[0][1]['mail'][0].decode("utf-8")
        last_name = result[0][1]['sn'][0].decode("utf-8")
        first_name = result[0][1]['givenName'][0].decode("utf-8")
        username = result[0][1]['SAMACCOUNTNAME'][0].decode("utf-8")
        user_dict = {
            'last_name': last_name,
            'first_name': first_name,
            'username': username,
            'email': mail,
            'source': self.search_source,
        }

        return user_dict

    def search_a_user(self, user_search_string=None, search_by='all_fields'):
        size_limit = 50
        if user_search_string and search_by == 'all_fields':
            filter = ldap.filter.filter_format("(|(givenName=*%s*)(sn=*%s*)(sAMAccountName=*%s*)(mail=*%s*))", [user_search_string] * 4)
        elif user_search_string and search_by == 'username_only':
            filter = ldap.filter.filter_format("(sAMAccountName=%s)", [user_search_string])
            size_limit = 1
        else:
            filter = '(objectclass=person)'

        search_base = self.LDAP_USER_SEARCH_BASE
        search_filter = filter
        search_attributes = ['givenName', 'sn', 'mail', 'sAMAccountName']
        result_set = []
        result_id = self.conn.search(search_base, ldap.SCOPE_SUBTREE, search_filter, search_attributes)
        while 1:
            result_type, result_data = self.conn.result(result_id, 0)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)

        users = []
        for idx, entry in enumerate(result_set, 1):
            user_dict = self.parse_ldap_entry(entry)
            users.append(user_dict)

        logger.info("LDAP user search for %s found %s results", user_search_string, len(users))
        return users

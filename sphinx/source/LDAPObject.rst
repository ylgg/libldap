LDAPObject classes
==================

.. py:class:: LDAPObject

   Instances of the class :py:class:`LDAPObject` are created either by
   calling the function :ref:`ldap_initialize() <ldap_initialize>`, or
   by calling the :py:class:`LDAP` class constructor. The two methods
   are stricly equivalent. More precisely,

   .. code-block:: python

      >>> l = ldap_initialize('ldap://host.test')

   is equivalent to:

   .. code-block:: python

      >>> l = LDAP('ldap://host.test')

   The connection is automatically unbound and closed when the LDAP
   object is deleted.

.. py:class:: LDAP(uri [, version=LDAP_VERSION3])

   An instance of the class :py:class:`LDAPObject` has the following
   attributes:

   .. py:attribute:: uri 

      LDAP URI (Uniform Resource Identifier):
      :py:const:`ldap[is]://host[:port]`

   .. py:attribute:: scheme

      URI scheme: :py:const:`ldap`, :py:const:`ldapi` or :py:const:`ldaps`

   .. py:attribute:: host

      LDAP host to contact		     

   .. py:attribute:: ip

      IPv4/v6 address of LDAP host to contact

   .. py:attribute:: port

      port on host (usually :py:const:`389` or :py:const:`636`)

   .. py:attribute:: dn

      To learn how *dn* attribute is used, refer to the
      documentation of the function :ref:`ldap_initialize()
      <ldap_initialize>`. This attribute can be modified at any time:

      .. code-block:: python

         >>> l = ldap_initialize('ldap://host.test')
	 >>> print(l.dn)
	 None
	 >>> l.dn = 'dc=example,dc=test'
	 >>> print(l.dn)
	 dc=example,dc=test
	 >>> l.dn = None

   Methods of the class :py:class:`LDAPObject` are:

   .. py:method:: simple_bind_s([user, password])

      Just after an :py:class:`LDAPObject` is created, it must be
      bound. If parameters *user* and *password* are not present, an
      *anonymous* bind is done

      :param str user: DN to bind as
      :param str password: userPassword associated with the entry
      :return: :py:const:`None`
      :raises: :py:exc:`LDAPError`

      .. seealso::
         :manpage:`ldap_simple_bind_s(3)`

   .. py:method:: bind_s([user, password, method=LDAP_AUTH_SIMPLE])

      Identical to method :py:meth:`simple_bind_s()` except for the
      extra *method* parameter selecting the authentication method to
      use. Only method :py:const:`LDAP_AUTH_SIMPLE` is currently
      available

      :param str user: DN to bind as
      :param str password: userPassword associated with the entry
      :param int method: authentication method to use
      :return: :py:const:`None`
      :raises: :py:exc:`LDAPError`

      .. seealso::
         :manpage:`ldap_bind_s(3)`

   .. py:method:: unbind_s()

      Unbind from the directory, terminate the current association,
      and free the resources previously allocated. Further invocation
      of methods on the object will yield exception
      :py:exc:`LDAPError`

      :return: :py:const:`None`
      :raises: :py:exc:`LDAPError`

      .. seealso::
         :manpage:`ldap_unbind_s(3)`

   .. py:method:: start_tls_s()

      Initiates TLS processing on an LDAP session

      :return: :py:const:`None`
      :raises: :py:exc:`LDAPError`

      .. seealso::
         :manpage:`ldap_start_tls_s(3)`

   .. py:method:: get_option(option)

      This routine is used to retreive options from an
      :py:class:`LDAPObject`. See :ref:`libldap-options` for available
      options.

      :param int option: global option to retreive
      :returns: option value
      :rtype: int
      :raises: :py:exc:`LDAPError`

      .. seealso::
         :manpage:`ldap_get_option(3)`

   .. py:method:: set_option(option, optval)

      This routine permits to set options for an
      :py:class:`LDAPObject`. See :ref:`libldap-options` for
      available options.

      :param int option: option to set
      :param int optval: option value
      :return: :py:const:`None`
      :raises: :py:exc:`LDAPError`

      .. seealso::
         :manpage:`ldap_set_option(3)`

   .. _operation-methods:

   .. py:method:: add_ext_s(dn, mods [, serverctrls [, clientctrls]])

      Performs an LDAP add operation

      :param str dn: the  DN  of the entry to add
      :param mods: a list of :ref:`LDAPMod <ldap-mod>`
                   objects. Attribute :py:attr:`mode` of each
                   :ref:`LDAPMod <ldap-mod>` object must be
                   :py:const:`LDAP_MOD_ADD`
      :param serverctrls: specifies server control(s). See section
        :ref:`Control methods <control-methods>`
      :type serverctrls: :py:class:`LDAPControls`
      :param clientctrls: specifies client control(s). See section
        :ref:`Control methods <control-methods>`
      :type clientctrls: :py:class:`LDAPControls`
      :return: :py:const:`None`
      :raises: :py:exc:`LDAPError`, :py:exc:`TypeError`

      .. seealso::
         :manpage:`ldap_add_ext_s(3)`

   .. py:method:: delete_ext_s(dn [, serverctrls [, clientctrls]])

      Performs an LDAP delete operation

      :param str dn: the  DN  of the entry to be deleted
      :param serverctrls: specifies server control(s). See section
        :ref:`Control methods <control-methods>`
      :type serverctrls: :py:class:`LDAPControls`
      :param clientctrls: specifies client control(s). See section
        :ref:`Control methods <control-methods>`
      :type clientctrls: :py:class:`LDAPControls`
      :return: :py:const:`None`
      :raises: :py:exc:`LDAPError`

      .. seealso::
         :manpage:`ldap_delete_ext_s(3)`

   .. py:method:: modify_ext_s(dn, mods [, serverctrls [, clientctrls]])

      Performs an LDAP modify operation

      :param str dn: the  DN  of the entry to modify
      :param mods: a list of :ref:`LDAPMod <ldap-mod>` objects. All
       modifications are performed in the order in which they are
       listed
      :param serverctrls: specifies server control(s). See section
        :ref:`Control methods <control-methods>`
      :type serverctrls: :py:class:`LDAPControls`
      :param clientctrls: specifies client control(s). See section
        :ref:`Control methods <control-methods>`
      :type clientctrls: :py:class:`LDAPControls`
      :return: :py:const:`None`
      :raises: :py:exc:`LDAPError`, :py:exc:`TypeError`

      .. code-block:: python

         >>> l = ldap_initialize('ldap://host.test/dc=example,dc=test')
         >>> l.start_tls_s()
	 >>> l.simple_bind_s(user='cn=admin', password='secret')
	 >>> lma = LDAPMod(LDAP_MOD_ADD, 'mailalias', ['bob@example.test'])
	 >>> lmr = LDAPMod(LDAP_MOD_REPLACE, 'givenName', ['Robert'])
	 >>> l.modify_ext_s('uid=bob,ou=users', [lma, lmr])

      .. seealso::
         :manpage:`ldap_modify_ext_s(3)`

   .. py:method:: search_ext_s([base [, scope [, filter [, attrs [, attrsonly [,serverctrls, [clientctrls [, limit [, timeout]]]]]]]]])

      Performs a LDAP search operation

      :param str base: DN of the entry at which to start the
                       search. If parameter *base* is not present,
                       attribute *dn* is used if it's not
                       :py:const:`None` otherwise exception
                       :py:exc:`LDAPError` is raised
      :param int scope: scope of the search. Default is
                        :py:const:`LDAP_SCOPE_SUBTREE` (search the object
                        and all its descendants). For other possible
                        values, see :ref:`scope constants <scope_constants>`
      :param str filter: filter to apply in the search. Default is
                         `'(objectClass=*)'`
      :param attrs: a list of attribute descriptions to return from
                    matching entries. If parameter *attrs* is not
                    present, all attributes are returned
      :type attrs: list of str(s)
      :param bool attrsonly: if :py:const:`True`, only attribute
                             descriptions are returned (attribute
                             values are then empty lists). Default is
                             :py:const:`False`
      :param serverctrls: specifies server control(s). See section
        :ref:`Control methods <control-methods>`
      :type serverctrls: :py:class:`LDAPControls`
      :param clientctrls: specifies client control(s). See section
        :ref:`Control methods <control-methods>`
      :type clientctrls: :py:class:`LDAPControls`
      :param int limit: size limit of the answer. Default is
                        :py:const:`LDAP_NO_LIMIT`
      :param int timeout: timeout in seconds to wait server
                          answer. :py:const:`0` means no timeout, this
                          is the default
      :return: a (possibly empty) list of results of the form: *[(dn,
               entry), ...]*. Each item of the list is 2-tuple where
               *dn* is a string containing the DN of the entry, and
               *entry* is a dictionary containing the attributes
               associated with the entry: *{attr: [value, ...],
               ...}*. For each entry in the dictionary, the key *attr*
               (string) is the attribute description and the
               corresponding value is the list of the
               associated values (strings)
      :raises: :py:exc:`LDAPError`, :py:exc:`TypeError`

      A simple example:

      .. code-block:: python

         >>> l = ldap_initialize('ldap://host.test/dc=example,dc=test')
         >>> l.start_tls_s()
	 >>> l.simple_bind_s()
         >>> l.search_ext_s(attrs=['uid'])
         [('uid=alice',ou=users,dc=example,dc=test', {'uid': ['alice']}), ('uid=bob,ou=users,dc=example,dc=test', {'uid': ['bob']})]

      .. seealso::
         :manpage:`ldap_search_ext_s(3)`

   .. py:method:: get_schema()

      retreives LDAP schema from server

      :return: [('cn=Subschema', entry)]
      :raises: :py:exc:`LDAPError`, :py:exc:`TypeError`

      More precisely, this function first executes the following
      statement:

      .. code-block:: python

         >>> schema = self.search_ext_s(LDAP_SCHEMA_BASE, scope=LDAP_SCOPE_BASE, attrs=['+'])

      The variable *schema* has the following form: *[('cn=Subschema',
      entry)]*. The function :py:meth:`get_schema()`, before returning
      *schema*, performs the following treatment: fields
      :py:const:`ldapSyntaxes`, :py:const:`matchingRules`,
      :py:const:`matchingRuleUse`, :py:const:`attributeTypes` and
      :py:const:`objectClasses` of dictionary *entry* are respectively
      parsed with :py:meth:`ldap_str2syntax`,
      :py:meth:`ldap_str2matchingrule`,
      :py:meth:`ldap_str2matchingruleuse`, 
      :py:meth:`ldap_str2attributetype` and
      :py:meth:`ldap_str2objectclass`. See section
      :ref:`schema_parsing_functions` for more details

   .. _control-methods:

   .. rubric:: Control methods

   .. py:method:: create_sort_control(keylist [, iscritical=False])

      builds a sort control

      :param str keylist: sort string. For example, if *keylist* is
        *'sn -givenName'* the search results are sorted first by surname
        and then by given name, with the given name being sorted in
        reverse (descending order) as specified by the prefixed minus
        sign (-)
      :param bool iscritical: the *iscritical* parameter is
                              :py:const:`True` non-zero for a critical
                              control, :py:const:`False` otherwise. Default
			      is :py:const:`False`
      :return: a new :py:class:`LDAPControl` object
      :raises: :py:exc:`LDAPError`, :py:exc:`TypeError`

   .. py:method:: create_assertion_control(filter [, iscritical=False])

      builds an assertion control

      :param str filter: control value (LDAP filter). See :rfc:`4528`
      :param bool iscritical: the *iscritical* parameter is
                              :py:const:`True` non-zero for a critical
                              control, :py:const:`False` otherwise. Default
			      is :py:const:`False`
      :return: a new :py:class:`LDAPControl` object
      :raises: :py:exc:`LDAPError`, :py:exc:`TypeError`

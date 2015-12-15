LDAPMod(s) classes
==================

.. _ldap-mod:

.. py:class:: LDAPMod(mode, attr [, values=None])

   This class is just a Python wrapper for the corresponding C
   structure :c:type:`LDAPMod` described in :manpage:`ldap_modify_ext_s(3)`

   :param mode: type of modification to perform
   :type mode: :py:const:`LDAP_MOD_ADD`, :py:const:`LDAP_MOD_DELETE`
               or :py:const:`LDAP_MOD_REPLACE`
   :param str attr: the attribute to modify
   :param values: a list of values (strings) to add, delete, or
       replace respectively or :py:const:`None` if the the entire
       attribute is to be deleted when parameter *mode* is
       :py:const:`LDAP_MOD_DELETE`
   :return: a new :py:class:`LDAPMod` object
   :raises: :py:exc:`TypeError`, :py:exc:`ValueError`

   An instance of the class :py:class:`LDAPMod` has the following
   attributes:

   .. py:attribute:: mode

      type of modification to perform (:py:const:`LDAP_MOD_ADD`,
      :py:const:`LDAP_MOD_DELETE` or :py:const:`LDAP_MOD_REPLACE`)

   .. py:attribute:: attr

      attribute to modify

   .. py:attribute:: values

      a list of values to add, delete, or replace respectively or
      :py:const:`None`

   Some examples:

   .. code-block:: python

      >>> lma = LDAPMod(LDAP_MOD_ADD, 'uid', ['bob'])
      >>> lmd = LDAPMod(LDAP_MOD_DELETE, 'uid')

   .. seealso::
      :manpage:`ldap_add_ext_s(3)`, :manpage:`ldap_modify_ext_s(3)`

.. py:class:: LDAPMods(mode, **attrs)

   This class is just a utility for regrouping classes
   :py:class:`LDAPMod` with the same mode. It is a subclass of Python
   class :py:class:`list`

   :param mode: type of modification to perform
   :type mode: :py:const:`LDAP_MOD_ADD`, :py:const:`LDAP_MOD_DELETE`
               or :py:const:`LDAP_MOD_REPLACE`
   :param dict attrs: attributes to modify
   :return: a list of :py:class:`LDAPMod` objects
   :raises: :py:exc:`LDAPError`, :py:exc:`TypeError` or :py:exc:`ValueError`

   So instead of writing,

   .. code-block:: python

      >>> lma = LDAPMod(LDAP_MOD_ADD, 'uid', ['bob'])
      >>> lmb = LDAPMod(LDAP_MOD_ADD, 'givenName', ['Robert'])
      >>> l.add_ext_s('ou=users', [lma, lmb])

   it is often shorter to write:

   .. code-block:: python

      >>> lm = LDAPMods(LDAP_MOD_ADD, uid=['bob'], givenName=['Robert'])
      >>> l.add_ext_s('ou=users', lm)

   or
 
   .. code-block:: python

      >>> d = {'uid': ['bob'], 'givenName': ['Robert']}
      >>> l.add_ext_s('ou=users', LDAPMods(LDAP_MOD_ADD, **d))    

LDAPControl(s) classes
======================

.. _ldap-control:

.. py:class:: LDAPControl()

   This class is just a Python wrapper for the corresponding C
   structure :c:type:`LDAPControl` (see :manpage:`ldap_controls(3)`)

   .. warning:: :py:class:`LDAPControl` object cannot be created
        directly. You have to use instead :ref:`create_*_control()
        <control-methods>` methods of a :py:class:`LDAP` object
        instance

.. py:class:: LDAPControls(<LDAPControl> [, <LDAPControl> ...])

   Classes :py:class:`LDAPControls` are the type of parameters
   *serverctrls* and *clientctrls* used to specify server and client
   controls respectively in :ref:`*_ext[_s]() <operation-methods>`
   methods of :py:class:`LDAP` objects. For example:

   .. code-block:: python

      >>> ca = l.create_assertion_control('(ou=users)', True)
      >>> cs = l.create_sort_control('sn -givenName')
      >>> ctrls = LDAPControls(ca, cs)
      >>> l.search_ext_s(serverctrls=ctrls)

   .. seealso::
      :manpage:`ldap_controls(3)`

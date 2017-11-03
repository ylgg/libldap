*****************************************************
:py:mod:`libldap` OpenLDAP C library interface module
*****************************************************

.. py:module:: libldap
    :platform: Posix
    :synopsis: OpenLDAP C library wrapper

Module `libldap` is a Python3 wrapper for OpenLDAP (Lightweight Directory
Access Protocol) C library.

Functions
=========

Following functions are defined by module `libldap`:

.. _ldap_initialize:

.. py:function:: ldap_initialize(uri [, version=LDAP_VERSION3]])

   Creates and initializes a new connection object (:py:class:`LDAPObject`) to
   access a LDAP server and returns this object.

   :param str uri: LDAP URI (Uniform Resource Identifier). It has the
                   following form: `ldap[is]://host[:port][/dn]`. This
                   parameter is identical to that of the underlying
                   function :c:func:`ldap_initialize` of the library
                   openLDAP except the optional `dn`. When this `dn`
                   is provided, each parameter of a method of an
                   instance of a :py:class:`LDAPObject` which is a DN,
                   is automatically completed by `dn` unless it
                   already ends with `dn`. For example, in the code below:

                   .. code-block:: python

                      >>> l = ldap_initialize('ldap:://host.test/dc=example,dc=test')
                      >>> l.simple_bind_s(user='cn=admin', password='secret')

		   parameter *user* is rewritten to
		   *'cn=admin,dc=example,dc=test'* before passed to the
		   underlying OpenLDAP library C function
   :param int version: version of LDAP protocol
   :type version: :py:const:`LDAP_VERSION2` or :py:const:`LDAP_VERSION3`
   :return: a new :py:class:`LDAPObject`
   :raises: :py:exc:`LDAPError`, :py:exc:`TypeError` or
            :py:exc:`ValueError`

   .. seealso::
      :manpage:`ldap_open(3)`

.. py:function:: ldap_get_option(option)

   This routine is used to retreive global options. See :ref:`libldap-options`
   for available options.

   :param int option: global option to retreive
   :returns: option value
   :rtype: int
   :raises: :py:exc:`LDAPError`

   For example, to get the peer certificate checking strategy:

   .. code-block:: python

      >>> ldap_get_option(LDAP_OPT_PROTOCOL_VERSION)
      2

   .. seealso::
      :manpage:`ldap_get_option(3)`

.. py:function:: ldap_set_option(option, optval)

   This routine permits to set global options. See :ref:`libldap-options` for
   available options.

   :param int option: global option to set
   :param int optval: option value
   :return: :py:const:`None`
   :raises: :py:exc:`LDAPError`

   For example, to set the peer certificate checking strategy:

   .. code-block:: python

       >>> ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_NEVER)

   .. seealso::
      :manpage:`ldap_set_option(3)`

.. py:function:: ldap_is_valid_dn(dn [, flags=LDAP_DN_FORMAT_LDAPV3])

   checks DN syntax

   :param str dn: DN to check
   :param flags: defines what DN syntax is expected (according to
                 :rfc:`4514`, :rfc:`1779` and **DCE**, respectively).
		 Parameter *flags* can also be ORed to the flag
		 :py:const:`LDAP_DN_PEDANTIC`
   :type flags: :py:const:`LDAP_DN_FORMAT_LDAPV3`,
                :py:const:`LDAP_DN_FORMAT_LDAPV2` or
                :py:const:`LDAP_DN_FORMAT_DCE`
   :return: :py:const:`True` if DN is valid, :py:const:`False` otherwise

   .. seealso::
      :manpage:`ldap_str2dn(3)`

.. _schema_parsing_functions:

Schema parsing functions
------------------------

These functions are used to parse schema definitions in the syntax
defined in RFC 4512 into Python dictionaries

.. py:function:: ldap_str2syntax(string [, flags])

   :param str string: the string to parse
   :param int flags: *flags* is a bit mask of parsing options
                     controlling the relaxation of the syntax
                     recognized. Default is
                     :py:const:`LDAP_SCHEMA_ALLOW_NONE`, see section
                     :ref:`schema_flags` for more details
   :return: :py:obj:`{'oid': <str>, 'names': <list_of_strs>, 'desc': <str>|None, 'extensions': (<str>, <list_of_strs>)|None}`
   :raises: :py:exc:`LDAPError`, :py:exc:`TypeError`

   The returned value is a Python dictionary corresponding to the
   C-structure :c:type:`LDAPSyntax` of the OpenLDAP library

   .. seealso::
      :manpage:`ldap_schema(3)`

.. py:function:: ldap_str2matchingrule(string [, flags])

   :param str string: the string to parse
   :param int flags: *flags* is a bit mask of parsing options
                     controlling the relaxation of the syntax
                     recognized. Default is
                     :py:const:`LDAP_SCHEMA_ALLOW_NONE`, see section
                     :ref:`schema_flags` for more details
   :return: :py:obj:`{'oid': <str>, 'names': <list_of_strs>, 'desc': <str>|None, 'obsolete': <bool>, 'syntax_oid': <str>|None, 'extensions': (<str>, <list_of_strs>)|None}`
   :raises: :py:exc:`LDAPError`, :py:exc:`TypeError`

   The returned value is a Python dictionary corresponding to the
   C-structure :c:type:`LDAPMatchingRule` of the OpenLDAP library

   .. seealso::
      :manpage:`ldap_schema(3)`

.. py:function:: ldap_str2matchingruleuse(string [, flags])

   :param str string: the string to parse
   :param int flags: *flags* is a bit mask of parsing options
                     controlling the relaxation of the syntax
                     recognized. Default is
                     :py:const:`LDAP_SCHEMA_ALLOW_NONE`, see section
                     :ref:`schema_flags` for more details
   :return: :py:obj:`{'oid': <str>, 'names': <list_of_strs>, 'desc': <str>|None, 'obsolete': <bool>, 'applies_oids': <list_of_strs>, 'extensions': (<str>, <list_of_strs>)|None}`
   :raises: :py:exc:`LDAPError`, :py:exc:`TypeError`

   The returned value is a Python dictionary corresponding to the
   C-structure :c:type:`LDAPMatchingRuleUse` of the OpenLDAP library

   .. seealso::
      :manpage:`ldap_schema(3)`

.. py:function:: ldap_str2attributetype(string [, flags])

   :param str string: the string to parse
   :param int flags: *flags* is a bit mask of parsing options
                     controlling the relaxation of the syntax
                     recognized. Default is
                     :py:const:`LDAP_SCHEMA_ALLOW_NONE`, see section
                     :ref:`schema_flags` for more details
   :return: :py:obj:`{'oid': <str>, 'names': <list_of_strs>, 'desc': <str>|None, 'obsolete': <bool>, 'sup_oid': <str>|None, 'equality_oid': <str>|None, 'ordering_oid': <str>|None, 'substr_oid': <str>|None, 'syntax_oid': <str>|None, 'syntax_len': <int>, 'single_value': <bool>, 'collective': <bool>, 'no_user_mod': <bool>, 'usage': <int>, 'extensions': (<str>, <list_of_strs>)|None}`
   :raises: :py:exc:`LDAPError`, :py:exc:`TypeError`

   The returned value is a Python dictionary corresponding to the
   C-structure :c:type:`LDAPAttributeType` of the OpenLDAP
   library. For possible values of the field *usage* see
   :ref:`schema_attribute_types`

   .. seealso::
      :manpage:`ldap_schema(3)`

.. py:function:: ldap_str2objectclass(string [, flags])

   :param str string: the string to parse
   :param int flags: *flags* is a bit mask of parsing options
                     controlling the relaxation of the objectclass
                     recognized. Default is
                     :py:const:`LDAP_SCHEMA_ALLOW_NONE`, see section
                     :ref:`schema_flags` for more details
   :return: :py:obj:`{'oid': <str>, 'names': <list_of_strs>, 'desc': <str>|None, 'obsolete': <bool>, 'sup_oids': <list_of_strs>, 'kind': <int>, 'oids_must': <list_of_strs>', 'oids_may': <list_of_strs>', extensions': (<str>, <list_of_strs>)|None}`
   :raises: :py:exc:`LDAPError`, :py:exc:`TypeError`

   The returned value is a Python dictionary corresponding to the
   C-structure :c:type:`LDAPObjectClass` of the OpenLDAP library. For
   possible values of the field *kind* see
   :ref:`schema_object_classes`

   .. seealso::
      :manpage:`ldap_schema(3)`

Examples
::::::::

.. code-block:: python

   >>> ldap_str2syntax("( 1.3.6.1.4.1.1466.115.121.1.4 DESC 'Audio' X-NOT-HUMAN-READABLE 'TRUE' )")
   {'extensions': [('X-NOT-HUMAN-READABLE', ['TRUE'])], 'oid': '1.3.6.1.4.1.1466.115.121.1.4', 'desc': 'Audio', 'names': []}
   >>> ldap_str2matchingrule("( 1.3.6.1.1.16.3 NAME 'UUIDOrderingMatch' SYNTAX 1.3.6.1.1.16.1 )")
   {'names': ['UUIDOrderingMatch'], 'desc': None, 'syntax_oid': '1.3.6.1.1.16.1', 'oid': '1.3.6.1.1.16.3', 'obsolete': False, 'extensions': None}

.. _libldap-constants:

Constants
=========

General
-------

.. py:data:: LDAP_VERSION2

.. py:data:: LDAP_VERSION3

.. py:data:: LDAP_NO_LIMIT

.. py:data:: LDAP_AUTH_SIMPLE

Modify constants
::::::::::::::::

.. py:data:: LDAP_MOD_ADD

.. py:data:: LDAP_MOD_DELETE

.. py:data:: LDAP_MOD_REPLACE

.. _scope_constants:

Scope constants
:::::::::::::::

.. py:data:: LDAP_SCOPE_BASE

   search the object itself

.. py:data:: LDAP_SCOPE_ONELEVEL

   search the object's immediate children

.. py:data:: LDAP_SCOPE_SUBTREE

   search the object and all its descendants

.. py:data:: LDAP_SCOPE_CHILDREN

   search all of the descendants

.. _libldap-sasl-constants:
   
SASL constants
::::::::::::::

.. py:data:: LDAP_SASL_AUTOMATIC

   use defaults if available, prompt otherwise

.. py:data:: LDAP_SASL_INTERACTIVE

   always prompt

.. py:data:: LDAP_SASL_QUIET

   never prompt

Schema constants
::::::::::::::::

.. seealso::
   :manpage:`ldap_schema(3)`

.. py:data:: LDAP_SCHEMA_BASE

   The base DN used to retreive an LDAP server schema. It is usually
   the string: :py:const:`'cn=Subschema'`

.. _schema_flags:

Flags
.....

.. py:data:: LDAP_SCHEMA_ALLOW_NONE

   Strict parsing according to RFC 4512

.. py:data:: LDAP_SCHEMA_ALLOW_NO_OID

   Permit definitions that do not contain an initial OID

.. py:data:: LDAP_SCHEMA_ALLOW_QUOTED

   Permit quotes around some items that should not have them

.. py:data:: LDAP_SCHEMA_ALLOW_DESCR

   Permit a descr instead of a numeric OID in places where the syntax
   expect the latter

.. py:data:: LDAP_SCHEMA_ALLOW_DESCR_PREFIX

   permit that the initial numeric OID contains a prefix in descr format

.. py:data:: LDAP_SCHEMA_ALLOW_ALL

   Be very liberal, include all options

.. _schema_attribute_types:

Attribute types
...............

.. py:data:: LDAP_SCHEMA_USER_APPLICATIONS

   The attribute type is non-operational

.. py:data:: LDAP_SCHEMA_DIRECTORY_OPERATION

   The attribute type is operational and is pertinent to the directory
   itself, i.e. it has the same value on all servers that master the
   entry containing this attribute type

.. py:data:: LDAP_SCHEMA_DISTRIBUTED_OPERATION

   The attribute type is operational and is pertinent to replication,
   shadowing or other distributed directory aspect

.. py:data:: LDAP_SCHEMA_DSA_OPERATION

   The attribute type is operational and is pertinent to the directory
   server itself, i.e. it may have different values for the same entry
   when retrieved from different servers that master the entry

.. _schema_object_classes:

Object classes
..............

.. py:data:: LDAP_SCHEMA_ABSTRACT

   The object class is abstract, i.e. there cannot be entries of this
   class alone

.. py:data:: LDAP_SCHEMA_STRUCTURAL

   The object class is structural, i.e. it describes the main role of
   the entry.  On some servers, once the entry is created the set of
   structural object classes assigned cannot be changed: none of those
   present can be removed and none other can be added

.. py:data:: LDAP_SCHEMA_AUXILIARY

   The object class is auxiliary, i.e. it is intended to go with
   other, structural, object classes. These can be added or removed
   at any time if attribute types are added or removed at the same
   time as needed by the set of object classes resulting from the
   operation

DN Constants
::::::::::::

.. py:data:: LDAP_DN_FORMAT_LDAPV3

.. py:data:: LDAP_DN_FORMAT_LDAPV2

.. py:data:: LDAP_DN_FORMAT_DCE

.. py:data:: LDAP_DN_PEDANTIC

   does not allow extra spaces in the DN

.. seealso::
   :manpage:`ldap_str2dn(3)`

.. _libldap-options:

Options
-------

.. py:data:: LDAP_OPT_PROTOCOL_VERSION


SASL options
::::::::::::

.. py:data:: LDAP_OPT_X_SASL_MECH

   to get the SASL mechanism

.. py:data:: LDAP_OPT_X_SASL_MECHLIST

   to get the list of the available SASL mechanisms. For example:

   .. code-block:: python

      >>> ldap_get_option(LDAP_OPT_X_SASL_MECHLIST)
      ('ANONYMOUS', 'LOGIN', 'PLAIN', 'CRAM-MD5', 'NTLM', 'EXTERNAL', 'DIGEST-MD5')

.. _libldap-tls-options:

TLS options
:::::::::::

.. py:data:: LDAP_OPT_X_TLS_REQUIRE_CERT

.. py:data:: LDAP_OPT_X_TLS_NEVER

.. py:data:: LDAP_OPT_X_TLS_HARD

.. py:data:: LDAP_OPT_X_TLS_DEMAND

.. py:data:: LDAP_OPT_X_TLS_ALLOW

.. py:data:: LDAP_OPT_X_TLS_TRY

Exceptions
==========

The module :py:mod:`libldap` defines only one exception:

.. py:exception:: LDAPError

   This exception is in particular thrown when a call to a function of
   the OpenLDAP library fails. In this case, the error message
   associated with this exception is the string returned by
   :c:func:`ldap_err2string` (see :manpage:`ldap_error(3)` for more
   details)

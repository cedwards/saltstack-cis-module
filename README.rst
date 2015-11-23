CIS compliance module
=====================

This module was designed to help facilitate compliance with the CIS standard.

:maintainer: Christer Edwards (cedwards@adobe.com)
:maturity: 20150901
:depends: none
:platform: centos 6/7

Currently this module supports CentOS 6 / 7, and only validates "Level 1 (Scored)" items.

Installation
------------

Place the `cis.py` module file into your ``salt/_modules`` directory and sync
the module to the required minions.

.. code-block:: shell

    salt '*' saltutil.sync_modules

Usage
-----

This module can run one, many or all checks as defined in the CIS standard. Examples respectively:

.. code-block:: shell

    salt '*' cis.audit_1_1_1
    salt '*' cis.audit_1_1 [details=True]
    salt '*' cis.audit [details=True]

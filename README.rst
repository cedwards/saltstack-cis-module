CIS compliance module
=====================

This module was designed to help facilitate compliance with the CIS standard. This document can be found at:
http://benchmarks.cisecurity.org/

:maintainer: Christer Edwards (cedwards@adobe.com)
:maturity: 20150729
:depends: none
:platform: centos 6.x

Currently this module supports only CentOS 6.

Usage
-----

This module can run one, many or all checks as defined in the CIS standard. Examples respectively:

.. code-block:: shell

    salt '*' cis.audit_1_1_1
    salt '*' cis.audit_1_1 [details=True]
    salt '*' cis.audit [details=True]

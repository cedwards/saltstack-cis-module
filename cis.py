# -*- coding: utf-8 -*-
'''
Center for Internet Security (CIS) audit module
'''
from __future__ import absolute_import

# Import python libs
import logging

# Import salt libs
from salt import utils

__virtualname__ = 'cis'

LOG = logging.getLogger(__name__)
GREP = utils.which('egrep')
STAT = utils.which('stat')
SYSCTL = utils.which('sysctl')
RPMQUERY = utils.which('rpm')

if utils.which('chkconfig'):
    CHKCONFIG = utils.which('chkconfig')
if utils.which('systemctl'):
    CHKCONFIG = utils.which('systemctl')

CIS = {}
CIS['Passed'] = []
CIS['Failed'] = []
CIS['Totals'] = {}
CIS['Details'] = {}
CIS['Totals']['Pass'] = 0
CIS['Totals']['Fail'] = 0


def __virtual__():
    '''
    Only load module on Linux
    '''
    if 'Linux' in __salt__['grains.get']('kernel'):
        return __virtualname__
    return False


def _grep(pattern, filename, shell=False):
    cmd = '{0} {1} {2}'.format(GREP, pattern, filename)
    return __salt__['cmd.run'](cmd, python_shell=shell)


def _stat(filename):
    '''
    Standard function for all ``stat`` commands.
    '''
    cmd = '{0} {1} {2}'.format(STAT, '-L -c "%a %u %g"', filename)
    return __salt__['cmd.run'](cmd, python_shell=False)


def _sysctl(keyname):
    cmd = '{0} {1}'.format(SYSCTL, keyname)
    return __salt__['cmd.run'](cmd, python_shell=False)


def _rpmquery(package):
    cmd = '{0} {1} {2}'.format(RPMQUERY, '-q', package)
    return __salt__['cmd.run'](cmd, python_shell=False)


def _chkconfig(service):
    if 'systemctl' in CHKCONFIG:
        cmd = '{0} {1} {2}'.format(CHKCONFIG, 'is-enabled', service)
    elif 'chkconfig' in CHKCONFIG:
        cmd = '{0} {1} {2}'.format(CHKCONFIG, '--list', service)
    return __salt__['cmd.run'](cmd, python_shell=False)


def audit_1_1(details=False):
    '''
    Audit Filesystem Configuration benchmarks (1.1)
    '''
    audit_1_1_1()
    audit_1_1_2()
    audit_1_1_3()
    audit_1_1_4()
    audit_1_1_5()
    audit_1_1_6()
    audit_1_1_7()
    audit_1_1_8()
    audit_1_1_9()
    audit_1_1_10()
    audit_1_1_14()
    audit_1_1_15()
    audit_1_1_16()
    audit_1_1_17()

    for benchmark in CIS['Passed']:
        CIS['Totals']['Pass'] += 1

    for benchmark in CIS['Failed']:
        CIS['Totals']['Fail'] += 1

    if details:
        return CIS
    else:
        return CIS['Totals']


def audit_1_1_1():
    '''
    Since the /tmp directory is intended to be world-writable, there is a risk
    of resource exhaustion if it is not bound to a separate partition. In
    addition, making /tmp its own file system allows an administrator to set
    the noexec option on the mount, making /tmp useless for an attacker to
    install executable code. It would also prevent an attacker from
    establishing a hardlink to a system setuid program and wait for it to be
    updated. Once the program was updated, the hardlink would be broken and the
    attacker would have his own copy of the program. If the program happened to
    have a security vulnerability, the attacker could continue to exploit the
    known flaw.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_1
    '''
    benchmark = '1.1.1 Create Separate Partition for /tmp (Scored)'

    ret = _grep('"/tmp"', '/etc/fstab')
    if ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_1_2():
    '''
    Since the /tmp filesystem is not intended to support devices, set this
    option to ensure that users cannot attempt to create block or character
    special devices in /tmp.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_2
    '''
    benchmark = '1.1.2 Set nodev option for /tmp partition (Scored)'

    ret = _grep('"/tmp"', '/etc/fstab')
    if 'nodev' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_1_3():
    '''
    Since the /tmp filesystem is only intended for temporary file storage, set this option to
    ensure that users cannot create set userid files in /tmp. 

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_3
    '''
    benchmark = '1.1.3 Set nosuid option for /tmp partition (Scored)'

    ret = _grep('"/tmp"', '/etc/fstab')
    if 'nosuid' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_1_4():
    '''
    Since the /tmp filesystem is only intended for temporary file storage, set
    this option to ensure that users cannot run executable binaries from /tmp.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_4
    '''
    benchmark = '1.1.4 Set noexec option for /tmp partition (Scored)'

    ret = _grep('"/tmp"', '/etc/fstab')
    if 'noexec' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_1_5():
    '''
    Since the /var directory may contain world-writable files and directories,
    there is a risk of resource exhaustion if it is not bound to a separate
    partition.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_5
    '''
    benchmark = '1.1.5 Create Separate Partition for /var (Scored)'

    ret = _grep('"/var"', '/etc/fstab')
    if ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_1_6():
    '''
    All programs that use /var/tmp and /tmp to read/write temporary files will
    always be written to the /tmp file system, preventing a user from running
    the /var file system out of space or trying to perform operations that have
    been blocked in the /tmp filesystem.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_6
    '''
    benchmark = '1.1.6 Bind mount the /var/tmp directory to /tmp (Scored)'

    ret = _grep('"^/tmp"', '/etc/fstab')
    if '/var/tmp' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_1_7():
    '''
    There are two important reasons to ensure that system logs are stored on a
    separate partition: protection against resource exhaustion (since logs can
    grow quite large) and protection of audit data.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_7
    '''
    benchmark = '1.1.7 Create separate partition for /var/log (Scored)'

    ret = _grep('"/var/log"', '/etc/fstab')
    if ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_1_8():
    '''
    There are two important reasons to ensure that data gathered by auditd is
    stored on a separate partition: protection against resource exhaustion
    (since the audit.log file can grow quite large) and protection of audit
    data. The audit daemon calculates how much free space is left and performs
    actions based on the results. If other processes (such as syslog) consume
    space in the same partition as auditd, it may not perform as desired.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_8
    '''
    benchmark = '1.1.8 Create separate partition for /var/log/audit (Scored)'

    ret = _grep('"/var/log/audit"', '/etc/fstab')
    if ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_1_9():
    '''
    If the system is intended to support local users, create a separate
    partition for the /home directory to protect against resource exhaustion
    and restrict the type of files that can be stored under /home.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_9
    '''
    benchmark = '1.1.9 Create separate partition for /home (Scored)'

    ret = _grep('"/home"', '/etc/fstab')
    if ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_1_10():
    '''
    Since the user partitions are not intended to support devices, set this
    option to ensure that users cannot attempt to create block or character
    special devices. 

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_10
    '''
    benchmark = '1.1.10 Add nodev option to /home (Scored)'

    ret = _grep('"/home"', '/etc/fstab')
    if 'nodev' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_1_14():
    '''
    Since the /dev/shm filesystem is not intended to support devices, set this
    option to ensure that users cannot attempt to create special devices in
    /dev/shm partitions.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_14
    '''
    benchmark = '1.1.14 Add nodev option to /dev/shm partition (Scored)'

    ret = _grep('"/dev/shm"', '/etc/fstab')
    if 'nodev' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_1_15():
    '''
    Setting this option on a file system prevents users from introducing
    privileged programs onto the system and allowing non-root users to execute
    them.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_15
    '''
    benchmark = '1.1.15 Add nosuid option to /dev/shm partition (Scored)'

    ret = _grep('"/dev/shm"', '/etc/fstab')
    if 'nosuid' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_1_16():
    '''
    Setting this option on a file system prevents users from executing programs
    from shared memory. This deters users from introducing potentially
    malicious software on the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_16
    '''
    benchmark = '1.1.16 Add noexec option to /dev/shm partition (Scored)'

    ret = _grep('"/dev/shm"', '/etc/fstab')
    if 'noexec' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_1_17():
    '''
    This feature prevents the ability to delete or rename files in world
    writable directories (such as /tmp) that are owned by another user.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_1_17
    '''
    benchmark = '1.1.17 Set sticky bit on all world-writable directories (Scored)'

    cmd = "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null"
    ret = __salt__['cmd.run'](cmd, python_shell=True)
    if not ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_2_2():
    '''
    It is important to ensure that an RPM's package signature is always checked
    prior to installation to ensure that the software is obtained from a trusted
    source.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_2_2
    '''
    benchmark = '1.2.2 Verify that gpgcheck is globally activated (Scored)'

    ret = _grep('gpgcheck=0', '/etc/yum.repos.d/*.repo', shell=True)
    if ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Passed'].append(benchmark)
    return CIS


def audit_1_5(details=False):
    '''
    Audit Filesystem Configuration benchmarks (1.5)
    '''
    audit_1_5_1()
    audit_1_5_2()
    audit_1_5_3()
    audit_1_5_4()
    audit_1_5_5()

    for benchmark in CIS['Passed']:
        CIS['Totals']['Pass'] += 1

    for benchmark in CIS['Failed']:
        CIS['Totals']['Fail'] += 1

    if details:
        return CIS
    else:
        return CIS['Totals']


def audit_1_5_1():
    '''
    Setting the owner and group to root prevents non-root users from changing the file.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_5_1
    '''
    benchmark = '1.5.1 Set user/group owner on /etc/grub.conf (Scored)'

    if 'systemctl' in CHKCONFIG:
        ret = _stat('/boot/grub2/grub.cfg')
    elif 'chkconfig' in CHKCONFIG:
        ret = _stat('/etc/grub.conf')

    if '0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_5_2():
    '''
    Setting the permissions to read and write for root only prevents non-root
    users from seeing the boot parameters or changing them. Non-root users who read
    the boot parameters may be able to identify weaknesses in security upon boot
    and be able to exploit them.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_5_2
    '''
    benchmark = '1.5.2 Set permissions on /etc/grub.conf (Scored)'

    if 'systemctl' in CHKCONFIG:
        ret = _stat('/boot/grub2/grub.cfg')
    elif 'chkconfig' in CHKCONFIG:
        ret = _stat('/etc/grub.conf')

    if '600' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_5_3():
    '''
    Requiring a boot password upon execution of the boot loader will prevent an
    unauthorized user from entering boot parameters or changing the boot partition.
    This prevents users from weakening security (e.g. turning off SELinux at boot
    time).

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_5_3
    '''
    benchmark = '1.5.3 Set boot loader password (Scored)'

    if 'systemctl' in CHKCONFIG:
        ret = _grep('"^password"', '/boot/grub2/grub.cfg')
    elif 'chkconfig' in CHKCONFIG:
        ret = _grep('"^password"', '/etc/grub.conf')

    if ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_5_4():
    '''
    Requiring authentication in single user mode prevents an unauthorized user
    from rebooting the system into single user to gain root privileges without
    credentials

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_5_4
    '''
    benchmark = '1.5.4 Require authentication for single-user mode (Scored)'

    ret = _grep('"^SINGLE"', '/etc/sysconfig/init')
    if 'sulogin' in ret:
        CIS['Passed'].append(benchmark)
    elif 'sushell' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_5_5():
    '''
    Requiring authentication in single user mode prevents an unauthorized user
    from rebooting the system into single user to gain root privileges without
    credentials

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_5_5
    '''
    benchmark = '1.5.5 Disable interactive boot (Scored)'

    ret = _grep('"^PROMPT"', '/etc/sysconfig/init')
    if ('no' or 'NO') in ret:
        CIS['Passed'].append(benchmark)
    elif ('yes' or 'YES') in ret:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_6(details=False):
    '''
    Audit Filesystem Configuration benchmarks (1.6)
    '''
    audit_1_6_1()
    audit_1_6_2()
    audit_1_6_3()

    for benchmark in CIS['Passed']:
        CIS['Totals']['Pass'] += 1

    for benchmark in CIS['Failed']:
        CIS['Totals']['Fail'] += 1

    if details:
        return CIS
    else:
        return CIS['Totals']


def audit_1_6_1():
    '''
    Setting a hard limit on core dumps prevents users from overriding the soft
    variable. If core dumps are required, consider setting limits for user groups
    (see limits.conf(5)). In addition, setting the fs.suid_dumpable variable to 0
    will prevent setuid programs from dumping core.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_6_1
    '''
    benchmark = '1.6.1 Restrict core dumps (Scored)'

    ret1 = _grep('"hard core"', '/etc/security/limits.conf')
    ret2 = _sysctl('fs.suid_dumpable')
    if (ret1 and (ret2 == '0')):
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_6_2():
    '''
    Enabling any feature that can protect against buffer overflow attacks
    enhances the security of the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_6_2
    '''
    benchmark = '1.6.2 Configure ExecShield (Scored)'

    ret = _sysctl('kernel.exec-shield')
    if '1' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_1_6_3():
    '''
    Randomly placing virtual memory regions will make it difficult for to write
    memory page exploits as the memory placement will be consistently shifting.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_1_6_3
    '''
    benchmark = '1.6.3 Enable randomized virtual memory region placement (Scored)'

    ret = _sysctl('kernel.randomize_va_space')
    if '2' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1(details=False):
    '''
    Audit Filesystem Configuration benchmarks (2.1)
    '''
    audit_2_1_1()
    audit_2_1_2()
    audit_2_1_3()
    audit_2_1_4()
    audit_2_1_5()
    audit_2_1_6()
    audit_2_1_7()
    audit_2_1_8()
    audit_2_1_9()
    audit_2_1_10()
    audit_2_1_11()
    audit_2_1_12()
    audit_2_1_13()
    audit_2_1_14()
    audit_2_1_15()
    audit_2_1_16()
    audit_2_1_17()
    audit_2_1_18()

    for benchmark in CIS['Passed']:
        CIS['Totals']['Pass'] += 1

    for benchmark in CIS['Failed']:
        CIS['Totals']['Fail'] += 1

    if details:
        return CIS
    else:
        return CIS['Totals']


def audit_2_1_1():
    '''
    The telnet protocol is insecure and unencrypted. The use of an unencrypted
    transmission medium could allow a user with access to sniff network traffic the
    ability to steal credentials. The ssh package provides an encrypted session and
    stronger security and is included in most Linux distributions.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_1
    '''
    benchmark = '2.1.1 Remove telnet-server (Scored)'

    ret = _rpmquery('telnet-server')
    if 'not installed' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_2():
    '''
    The telnet protocol is insecure and unencrypted. The use of an unencrypted
    transmission medium could allow an authorized user to steal credentials. The
    ssh package provides an encrypted session and stronger security and is included
    in most Linux distributions

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_2
    '''
    benchmark = '2.1.2 Remove telnet client (Scored)'

    ret = _rpmquery('telnet')
    if 'not installed' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_3():
    '''
    These legacy service contain numerous security exposures and have been
    replaced with the more secure SSH package.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_3
    '''
    benchmark = '2.1.3 Remove rsh-server (Scored)'

    ret = _rpmquery('rsh-server')
    if 'not installed' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_4():
    '''
    These legacy clients contain numerous security exposures and have been
    replaced with the more secure SSH package. Even if the server is removed, it is
    best to ensure the clients are also removed to prevent users from inadvertently
    attempting to use these commands and therefore exposing their credentials. Note
    that removing the rsh package removes the clients for rsh, rcp and rlogin.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_4
    '''
    benchmark = '2.1.4 Remove rsh (Scored)'

    ret = _rpmquery('rsh')
    if 'not installed' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_5():
    '''
    The NIS service is inherently an insecure system that has been vulnerable
    to DOS attacks, buffer overflows and has poor authentication for querying NIS
    maps. NIS generally has been replaced by such protocols as Lightweight
    Directory Access Protocol (LDAP). It is recommended that the service be
    removed.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_5
    '''
    benchmark = '2.1.5 Remove NIS client (Scored)'

    ret = _rpmquery('ypbind')
    if 'not installed' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_6():
    '''
    The NIS service is inherently an insecure system that has been vulnerable
    to DOS attacks, buffer overflows and has poor authentication for querying NIS
    maps. NIS generally been replaced by such protocols as Lightweight Directory
    Access Protocol (LDAP). It is recommended that the service be disabled and
    other, more secure services be used.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_6
    '''
    benchmark = '2.1.6 Remove NIS server (Scored)'

    ret = _rpmquery('ypserv')
    if 'not installed' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_7():
    '''
    It is recommended that TFTP be removed, unless there is a specific need for
    TFTP (such as a boot server). In that case, use extreme caution when
    configuring the services.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_7
    '''
    benchmark = '2.1.7 Remove tftp (Scored)'

    ret = _rpmquery('tftp')
    if 'not installed' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_8():
    '''
    TFTP does not support authentication nor does it ensure the confidentiality
    of integrity of data. It is recommended that TFTP be removed, unless there is a
    specific need for TFTP. In that case, extreme caution must be used when
    configuring the services.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_8
    '''
    benchmark = '2.1.8 Remove tftp-server (Scored)'

    ret = _rpmquery('tftp-server')
    if 'not installed' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_9():
    '''
    The software presents a security risk as it uses unencrypted protocols for
    communication.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_9
    '''
    benchmark = '2.1.9 Remove talk (Scored)'

    ret = _rpmquery('talk')
    if 'not installed' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_10():
    '''
    The software presents a security risk as it uses unencrypted protocols for
    communication.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_10
    '''
    benchmark = '2.1.10 Remove talk-server (Scored)'

    ret = _rpmquery('talk-server')
    if 'not installed' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_11():
    '''
    If there are no xinetd services required, it is recommended that the daemon
    be deleted from the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_11
    '''
    benchmark = '2.1.11 Remove xinetd (Scored)'

    ret = _rpmquery('xinetd')
    if 'not installed' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_12():
    '''
    Disabling this service will reduce the remote attack surface of the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_12
    '''
    benchmark = '2.1.12 Disable chargen-dgram (Scored)'

    ret = _chkconfig('chargen-dgram')
    if 'No such file or directory' in ret:
        CIS['Passed'].append(benchmark)
    elif 'off' in ret:
        CIS['Passed'].append(benchmark)
    elif 'enabled' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_13():
    '''
    Disabling this service will reduce the remote attack surface of the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_13
    '''
    benchmark = '2.1.13 Disable chargen-stream (Scored)'

    ret = _chkconfig('chargen-stream')
    if 'No such file or directory' in ret:
        CIS['Passed'].append(benchmark)
    elif 'off' in ret:
        CIS['Passed'].append(benchmark)
    elif 'enabled' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_14():
    '''
    Disabling this service will reduce the remote attack surface of the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_14
    '''
    benchmark = '2.1.14 Disable daytime-dgram (Scored)'

    ret = _chkconfig('daytime-dgram')
    if 'No such file or directory' in ret:
        CIS['Passed'].append(benchmark)
    elif 'off' in ret:
        CIS['Passed'].append(benchmark)
    elif 'enabled' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_15():
    '''
    Disabling this service will reduce the remote attack surface of the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_15
    '''
    benchmark = '2.1.15 Disable daytime-stream (Scored)'

    ret = _chkconfig('daytime-stream')
    if 'No such file or directory' in ret:
        CIS['Passed'].append(benchmark)
    elif 'off' in ret:
        CIS['Passed'].append(benchmark)
    elif 'enabled' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_16():
    '''
    Disabling this service will reduce the remote attack surface of the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_16
    '''
    benchmark = '2.1.16 Disable echo-dgram (Scored)'

    ret = _chkconfig('echo-dgram')
    if 'No such file or directory' in ret:
        CIS['Passed'].append(benchmark)
    elif 'off' in ret:
        CIS['Passed'].append(benchmark)
    elif 'enabled' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_17():
    '''
    Disabling this service will reduce the remote attack surface of the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_17
    '''
    benchmark = '2.1.17 Disable echo-stream (Scored)'

    ret = _chkconfig('echo-stream')
    if 'No such file or directory' in ret:
        CIS['Passed'].append(benchmark)
    elif 'off' in ret:
        CIS['Passed'].append(benchmark)
    elif 'enabled' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_2_1_18():
    '''
    tcpmux-server can be abused to circumvent the server's host based firewall.
    Additionally, tcpmux-server can be leveraged by an attacker to effectively port
    scan the server.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_18
    '''
    benchmark = '2.1.18 Disable tcpmux-server (Scored)'

    ret = _chkconfig('tcpmux-server')
    if 'No such file or directory' in ret:
        CIS['Passed'].append(benchmark)
    elif 'off' in ret:
        CIS['Passed'].append(benchmark)
    elif 'enabled' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_3(details=False):
    '''
    Audit Filesystem Configuration benchmarks (3)
    '''
    audit_3_1()
    audit_3_2()
    audit_3_3()
    audit_3_5()
    audit_3_6()
    audit_3_16()

    for benchmark in CIS['Passed']:
        CIS['Totals']['Pass'] += 1

    for benchmark in CIS['Failed']:
        CIS['Totals']['Fail'] += 1

    if details:
        return CIS
    else:
        return CIS['Totals']


def audit_3_1():
    '''
    Setting the umask to 027 will make sure that files created by daemons will
    not be readable, writable or executable by any other than the group and owner
    of the daemon process and will not be writable by the group of the daemon
    process. The daemon process can manually override these settings if these files
    need additional permission.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_18
    '''
    benchmark = '3.1 Set Daemon umask (Scored)'

    ret = _grep('"umask"', '/etc/sysconfig/init')
    if 'umask 027' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_3_2():
    '''
    Unless your organization specifically requires graphical login access via X
    Windows, remove it to reduce the potential attack surface

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_18
    '''
    benchmark = '3.2 Remove X Windows (Scored)'

    ret = _grep('"^id"', '/etc/inittab')
    if 'id:3:initdefault' in ret:
        CIS['Passed'].append(benchmark)
    elif 'id:5:initdefault' in ret:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_3_3():
    '''
    Since servers are not normally used for printing, this service is not
    needed unless dependencies require it. If this is the case, disable the service
    to reduce the potential attack surface. If for some reason the service is
    required on the server, follow the recommendations in sub-sections 3.2.1 -
    3.2.5 to secure it.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_18
    '''
    benchmark = '3.3 Disable avahi server (Scored)'

    ret = _chkconfig('avahi-daemon')
    if 'No such file or directory' in ret:
        CIS['Passed'].append(benchmark)
    elif 'on' in ret:
        CIS['Failed'].append(benchmark)
    elif 'enabled' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_3_5():
    '''
    Unless a server is specifically set up to act as a DHCP server, it is
    recommended that this service be deleted to reduce the potential attack
    surface.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_18
    '''
    benchmark = '3.5 Remove DHCP server (Scored)'

    ret = _rpmquery('dhcp')
    if 'not installed' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_3_6():
    '''
    It is recommended that physical systems and virtual guests lacking direct
    access to the physical host's clock be configured as NTP clients to synchronize
    their clocks (especially to support time sensitive security mechanisms like
    Kerberos). This also ensures log files have consistent time records across the
    enterprise, which aids in forensic investigations.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_18
    '''
    benchmark = '3.6 Configure network time protocol (NTP) (Scored)'

    ret = _grep('"restrict default"', '/etc/ntp.conf')
    if ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_3_16():
    '''
    The software for all Mail Transfer Agents is complex and most have a long
    history of security issues. While it is important to ensure that the system can
    process local mail messages, it is not necessary to have the MTA's daemon
    listening on a port unless the server is intended to be a mail server that
    receives and processes mail from other systems.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_2_1_18
    '''
    benchmark = '3.16 Configure mail transfer agent for local-only mode (Scored)'

    cmd = 'netstat -an | grep LIST | grep ":25[[:space:]]"'
    ret = __salt__['cmd.run'](cmd, python_shell=True)
    if '127.0.0.1' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_4_1_1():
    '''
    Setting the flag to 0 ensures that a server with multiple interfaces (for
    example, a hard proxy), will never be able to forward packets, and therefore,
    never serve as a router

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_4_1_1
    '''
    benchmark = '4.1.1 Disable IP forwarding (Scored)'

    ret = _sysctl('net.ipv4.ip_forward')
    if '0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_4_1_2():
    '''
    An attacker could use a compromised host to send invalid ICMP redirects to
    other router devices in an attempt to corrupt routing and have users access a
    system set up by the attacker as opposed to a valid system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_4_1_2
    '''
    benchmark = '4.1.2 Disable send packet redirects (Scored)'

    ret1 = _sysctl('net.ipv4.conf.all.send_redirects')
    ret2 = _sysctl('net.ipv4.conf.default.send_redirects')
    if ('0' in ret1 and '0' in ret2):
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_4_2_1():
    '''
    Setting net.ipv4.conf.all.accept_source_route and
    net.ipv4.conf.default.accept_source_route to 0 disables the system from
    accepting source routed packets. Assume this server was capable of routing
    packets to Internet routable addresses on one interface and private addresses
    on another interface. Assume that the private addresses were not routable to
    the Internet routable addresses and vice versa. Under normal routing
    circumstances, an attacker from the Internet routable addresses could not use
    the server as a way to reach the private address servers. If, however, source
    routed packets were allowed, they could be used to gain access to the private
    address systems as the route could be specified, rather than rely on routing
    protocols that did not allow this routing.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_4_2_1
    '''
    benchmark = '4.2.1 disable source routed packet acceptance (Scored)'

    ret1 = _sysctl('net.ipv4.conf.all.accept_source_route')
    ret2 = _sysctl('net.ipv4.conf.default.accept_source_route')
    if ('0' in ret1 and '0' in ret2):
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_4_2_2():
    '''
    Attackers could use bogus ICMP redirect messages to maliciously alter the
    system routing tables and get them to send packets to incorrect networks and
    allow your system packets to be captured.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_4_2_2
    '''
    benchmark = '4.2.2 Disable ICMP redirect acceptance (Scored)'

    ret1 = _sysctl('net.ipv4.conf.all.accept_redirects')
    ret2 = _sysctl('net.ipv4.conf.default.accept_redirects')
    if ('0' in ret1 and '0' in ret2):
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_4_2_4():
    '''
    Enabling this feature and logging these packets allows an administrator to
    investigate the possibility that an attacker is sending spoofed packets to
    their server.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_4_2_4
    '''
    benchmark = '4.2.4 Log suspicious packets (Scored)'

    ret1 = _sysctl('net.ipv4.conf.all.log_martians')
    ret2 = _sysctl('net.ipv4.conf.default.log_martians')
    if ('1' in ret1 and '1' in ret2):
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_4_2_5():
    '''
    Accepting ICMP echo and timestamp requests with broadcast or multicast
    destinations for your network could be used to trick your host into starting
    (or participating) in a Smurf attack. A Smurf attack relies on an attacker
    sending large amounts of ICMP broadcast messages with a spoofed source address.
    All hosts receiving this message and responding would send echo-reply messages
    back to the spoofed address, which is probably not routable. If many hosts
    respond to the packets, the amount of traffic on the network could be
    significantly multiplied.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_4_2_5
    '''
    benchmark = '4.2.5 Enable ignore broadcast requests (Scored)'

    ret = _sysctl('net.ipv4.icmp_echo_ignore_broadcasts')
    if '1' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_4_2_6():
    '''
    Some routers (and some attackers) will send responses that violate RFC-1122
    and attempt to fill up a log file system with many useless error messages.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_4_2_6
    '''
    benchmark = '4.2.6 Enable bad error message protection (Scored)'

    ret = _sysctl('net.ipv4.icmp_ignore_bogus_error_response')
    if '1' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_4_2_8():
    '''
    Attackers use SYN flood attacks to perform a denial of service attacked on
    a server by sending many SYN packets without completing the three way
    handshake. This will quickly use up slots in the kernel's half-open connection
    queue and prevent legitimate connections from succeeding. SYN cookies allow the
    server to keep accepting valid connections, even if under a denial of service
    attack.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_4_2_8
    '''
    benchmark = '4.2.8 Enable TCP SYN cookies (Scored)'

    ret = _sysctl('net.ipv4.tcp_syncookies')
    if '1' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_4_5_3():
    '''
    It is critical to ensure that the /etc/hosts.allow file is protected from
    unauthorized write access. Although it is protected by default, the file
    permissions could be changed either inadvertently or through malicious actions.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_4_5_3
    '''
    benchmark = '4.5.3 Verify permissions on /etc/hosts.allow (Scored)'

    ret = _stat('/etc/hosts.allow')
    if '644' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_4_5_5():
    '''
    It is critical to ensure that the /etc/hosts.deny file is protected from
    unauthorized write access. Although it is protected by default, the file
    permissions could be changed either inadvertently or through malicious actions.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_4_5_5
    '''
    benchmark = '4.5.5 Verify permissions on /etc/hosts.deny (Scored)'

    ret = _stat('/etc/hosts.deny')
    if '644' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_4_7():
    '''
    IPtables provides extra protection for the Linux system by limiting
    communications in and out of the box to specific IPv4 addresses and ports.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_4_5_7
    '''
    benchmark = '4.7 Enable iptables / firewalld (Scored)'

    if 'systemctl' in CHKCONFIG:
        ret = _chkconfig('firewalld')
    if 'chkconfig' in CHKCONFIG:
        ret = _chkconfig('iptables')

    if '3:on' in ret:
        CIS['Passed'].append(benchmark)
    elif 'enabled' in ret:
        CIS['Passed'].append(benchmark)
    elif 'No such file or directory' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_5_1_1():
    '''
    The security enhancements of rsyslog such as connection-oriented (i.e. TCP)
    transmission of logs, the option to log to database formats, and the encryption
    of log data en route to a central logging server) justify installing and
    configuring the package.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_5_1_1
    '''
    benchmark = '5.1.1 Install the rsyslog package (Scored)'

    ret = _rpmquery('rsyslog')
    if 'not installed' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Passed'].append(benchmark)
    return CIS


def audit_5_1_2():
    '''
    It is important to ensure that syslog is turned off so that it does not
    interfere with the rsyslog service.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_5_1_2
    '''
    benchmark = '5.1.2 Activate the rsyslog service (Scored)'

    ret = _chkconfig('rsyslog')
    if '3:on' in ret:
        CIS['Passed'].append(benchmark)
    elif 'enabled' in ret:
        CIS['Passed'].append(benchmark)
    elif 'No such file or directory' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_5_1_5():
    '''
    Storing log data on a remote host protects log integrity from local
    attacks. If an attacker gains root access on the local system, they could
    tamper with or remove log data that is stored on the local system

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_5_1_5
    '''
    benchmark = '5.1.5 Configure rsyslog to send logs to a remote log host (Scored)'

    ret = _grep('"^*.* @"', '/etc/rsyslog.conf')
    if ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_1_1():
    '''
    Cron jobs may include critical security or administrative functions that
    need to run on a regular basis. Use this daemon on machines that are not up
    24x7, or if there are jobs that need to be executed after the system has been
    brought back up after a maintenance window.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_1_1
    '''
    benchmark = '6.1.1 Enable anacron daemon (Scored)'

    ret = _rpmquery('cronie-anacron')
    if 'not installed' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Passed'].append(benchmark)
    return CIS


def audit_6_1_2():
    '''
    While there may not be user jobs that need to be run on the system, the
    system does have maintenance jobs that may include security monitoring that
    have to run and crond is used to execute them.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_1_2
    '''
    benchmark = '6.1.2 Enable crond daemon (Scored)'

    ret = _chkconfig('crond')
    if '3:on' in ret:
        CIS['Passed'].append(benchmark)
    elif 'enabled' in ret:
        CIS['Passed'].append(benchmark)
    elif 'No such file or directory' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_1_3():
    '''
    This file contains information on what system jobs are run by anacron.
    Write access to these files could provide unprivileged users with the ability
    to elevate their privileges. Read access to these files could provide users
    with the ability to gain insight on system jobs that run on the system and
    could provide them a way to gain unauthorized privileged access.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_1_3
    '''
    benchmark = '6.1.3 Set user/group owner and permission on /etc/anacrontab (Scored)'

    ret = _stat('/etc/anacrontab')
    if '600 0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_1_4():
    '''
    This file contains information on what system jobs are run by cron. Write
    access to these files could provide unprivileged users with the ability to
    elevate their privileges. Read access to these files could provide users with
    the ability to gain insight on system jobs that run on the system and could
    provide them a way to gain unauthorized privileged access.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_1_4
    '''
    benchmark = '6.1.4 Set user/group owner and permission on /etc/crontab (Scored)'

    ret = _stat('/etc/crontab')
    if '600 0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_1_5():
    '''
    Granting write access to this directory for non-privileged users could
    provide them the means for gaining unauthorized elevated privileges. Granting
    read access to this directory could give an unprivileged user insight in how to
    gain elevated privileges or circumvent auditing controls.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_1_5
    '''
    benchmark = '6.1.5 Set user/group and permission on /etc/cron.hourly (Scored)'

    ret = _stat('/etc/cron.hourly')
    if '600 0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_1_6():
    '''
    Granting write access to this directory for non-privileged users could
    provide them the means for gaining unauthorized elevated privileges. Granting
    read access to this directory could give an unprivileged user insight in how to
    gain elevated privileges or circumvent auditing controls.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_1_6
    '''
    benchmark = '6.1.6 Set user/group and permission on /etc/cron.daily (Scored)'

    ret = _stat('/etc/cron.daily')
    if '600 0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_1_7():
    '''
    Granting write access to this directory for non-privileged users could
    provide them the means for gaining unauthorized elevated privileges. Granting
    read access to this directory could give an unprivileged user insight in how to
    gain elevated privileges or circumvent auditing controls.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_1_7
    '''
    benchmark = '6.1.7 Set user/group owner and permission on /etc/cron.weekly (Scored)'

    ret = _stat('/etc/cron.weekly')
    if '600 0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_1_8():
    '''
    Granting write access to this directory for non-privileged users could
    provide them the means for gaining unauthorized elevated privileges. Granting
    read access to this directory could give an unprivileged user insight in how to
    gain elevated privileges or circumvent auditing controls.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_1_8
    '''
    benchmark = '6.1.8 Set user/group owner and permission on /etc/cron.monthly (Scored)'

    ret = _stat('/etc/cron.monthly')
    if '600 0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_1_9():
    '''
    Granting write access to this directory for non-privileged users could
    provide them the means for gaining unauthorized elevated privileges. Granting
    read access to this directory could give an unprivileged user insight in how to
    gain elevated privileges or circumvent auditing controls.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_1_9
    '''
    benchmark = '6.1.9 Set user/group owner and permission on /etc/cron.d (Scored)'

    ret = _stat('/etc/cron.d')
    if '600 0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_1_10():
    '''
    Granting write access to this directory for non-privileged users could
    provide them the means to gain unauthorized elevated privileges. Granting read
    access to this directory could give an unprivileged user insight in how to gain
    elevated privileges or circumvent auditing controls. In addition, it is a
    better practice to create a white list of users who can execute at jobs versus
    a blacklist of users who can't execute at jobs as a system administrator will
    always know who can create jobs and does not have to worry about remembering to
    add a user to the blacklist when a new user id is created.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_1_10
    '''
    benchmark = '6.1.10 Restrict at daemon (Scored)'

    ret = _stat('/etc/at.allow')
    if '600 0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_1_11():
    '''
    On many systems, only the system administrator is authorized to schedule
    cron jobs. Using the cron.allow file to control who can run cron jobs enforces
    this policy. It is easier to manage an allow list than a deny list. In a deny
    list, you could potentially add a user ID to the system and forget to add it to
    the deny files.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_1_11
    '''
    benchmark = '6.1.11 Restrict at/cron to authorized users (Scored)'

    ret1 = _stat('/etc/cron.deny')
    ret2 = _stat('/etc/at.deny')
    ret3 = _stat('/etc/cron.allow')
    ret4 = _stat('/etc/at.allow')
    if (('600 0 0' in ret3 and '600 0 0' in ret4) and
       ('cannot stat' in ret1 and 'cannot stat' in ret2)):
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_2_1():
    '''
    SSH v1 suffers from insecurities that do not affect SSH v2.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_1
    '''
    benchmark = '6.2.1 Set SSH protocol to 2 (Scored)'

    ret = _grep('"^Protocol"', '/etc/ssh/sshd_config')
    if 'Protocol 2' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_2(details=False):
    '''
    Audit Filesystem Configuration benchmarks (1.1)
    '''
    audit_6_2_2()
    audit_6_2_3()
    audit_6_2_4()
    audit_6_2_5()
    audit_6_2_6()
    audit_6_2_7()
    audit_6_2_8()
    audit_6_2_9()
    audit_6_2_10()
    audit_6_2_11()
    audit_6_2_12()
    audit_6_2_13()
    audit_6_2_14()

    for benchmark in CIS['Passed']:
        CIS['Totals']['Pass'] += 1

    for benchmark in CIS['Failed']:
        CIS['Totals']['Fail'] += 1

    if details:
        return CIS
    else:
        return CIS['Totals']


def audit_6_2_2():
    '''
    SSH provides several logging levels with varying amounts of verbosity.
    DEBUG is specifically not recommended other than strictly for debugging SSH
    communications since it provides so much data that it is difficult to identify
    important security information. INFO level is the basic level that only records
    login activity of SSH users. In many situations, such as Incident Response, it
    is important to determine when a particular user was active on a system. The
    logout record can eliminate those users who disconnected, which helps narrow
    the field.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_2
    '''
    benchmark = '6.2.2 Set LogLevel to INFO (Scored)'

    ret = _grep('"^LogLevel"', '/etc/ssh/sshd_config')
    if 'LogLevel INFO' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_2_3():
    '''
    The /etc/ssh/sshd_config file needs to be protected from unauthorized
    changes by nonpriliveged users, but needs to be readable as this information is
    used with many nonprivileged programs.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_3
    '''
    benchmark = '6.2.3 Set permissions on /etc/ssh/sshd_config (Scored)'

    ret = _stat('/etc/ssh/sshd_config')
    if '600 0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_2_4():
    '''
    Disable X11 forwarding unless there is an operational requirement to use
    X11 applications directly. There is a small risk that the remote X11 servers of
    users who are logged in via SSH with X11 forwarding could be compromised by
    other users on the X11 server. Note that even if X11 forwarding is disabled,
    users can always install their own forwarders.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_4
    '''
    benchmark = '6.2.4 disable SSH X11 forwarding (Scored)'

    ret = _grep('"^X11Forwarding"', '/etc/ssh/sshd_config')
    if 'X11Forwarding no' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_2_5():
    '''
    Setting the MaxAuthTries parameter to a low number will minimize the risk
    of successful brute force attacks to the SSH server. While the recommended
    setting is 4, it is set the number based on site policy.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_5
    '''
    benchmark = '6.2.5 Set SSH maxAuthTries to 4 or less (Scored)'

    ret = _grep('"^MaxAuthTries"', '/etc/ssh/sshd_config')
    if ('1' or '2' or '3' or '4') in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_2_6():
    '''
    Setting this parameter forces users to enter a password when authenticating
    with ssh.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_6
    '''
    benchmark = '6.2.6 Set SSH IgnoreRhosts to Yes (Scored)'

    ret = _grep('"^IgnoreRhosts"', '/etc/ssh/sshd_config')
    if 'IgnoreRhosts yes' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_2_7():
    '''
    Even though the .rhosts files are ineffective if support is disabled in
    /etc/pam.conf, disabling the ability to use .rhosts files in SSH provides an
    additional layer of protection.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_7
    '''
    benchmark = '6.2.7 Set SSH HostbasedAuthentication to No (Scored)'

    ret = _grep('"HostbasedAuthentication"', '/etc/ssh/sshd_config')
    if 'HostbasedAuthentication no' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_2_8():
    '''
    Disallowing root logins over SSH requires server admins to authenticate
    using their own individual account, then escalating to root via sudo or su.
    This in turn limits opportunity for non-repudiation and provides a clear audit
    trail in the event of a security incident

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_8
    '''
    benchmark = '6.2.8 Disable SSH Root Login (Scored)'

    ret = _grep('"^PermitRootLogin"', '/etc/ssh/sshd_config')
    if 'PermitRootLogin no' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_2_9():
    '''
    Disallowing remote shell access to accounts that have an empty password
    reduces the probability of unauthorized access to the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_9
    '''
    benchmark = '6.2.9 Set SSH PermitEmptyPasswords to No (Scored)'

    ret = _grep('"^PermitEmptyPasswords"', '/etc/ssh/sshd_config')
    if 'PermitEmptyPasswords no' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_2_10():
    '''
    Permitting users the ability to set environment variables through the SSH
    daemon could potentially allow users to bypass security controls (e.g. setting
    an execution path that has ssh executing trojan'd programs)

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_10
    '''
    benchmark = '6.2.10 Do not allow users to set environment options (Scored)'

    ret = _grep('"^PermitUserEnvironment"', '/etc/ssh/sshd_config')
    if 'PermitUserEnvironment no' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_2_11():
    '''
    Based on research conducted at various institutions, it was determined that
    the symmetric portion of the SSH Transport Protocol (as described in RFC 4253)
    has security weaknesses that allowed recovery of up to 32 bits of plaintext
    from a block of ciphertext that was encrypted with the Cipher Block Chaining
    (CBD) method. From that research, new Counter mode algorithms (as described in
    RFC4344) were designed that are not vulnerable to these types of attacks and
    these algorithms are now recommended for standard use.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_11
    '''
    benchmark = '6.2.11 Use only approvide cipher in counter mode (Scored)'

    ret = _grep('"^Ciphers"', '/etc/ssh/sshd_config')
    if not ('aes128-ctr' or 'aes192-ctr' or 'aes256-ctr') in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Passed'].append(benchmark)
    return CIS


def audit_6_2_12():
    '''
    Having no timeout value associated with a connection could allow an
    unauthorized user access to another user's ssh session (e.g. user walks away
    from their computer and doesn't lock the screen). Setting a timeout value at
    least reduces the risk of this happening..  While the recommended setting is
    300 seconds (5 minutes), set this timeout value based on site policy. The
    recommended setting for ClientAliveCountMax is 0. In this case, the client
    session will be terminated after 5 minutes of idle time and no keepalive
    messages will be sent.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_12
    '''
    benchmark = '6.2.12 Set Idle timeout interval for user login (Scored)'

    ret1 = _grep('"^ClientAliveInterval"', '/etc/ssh/sshd_config')
    ret2 = _grep('"^ClientAliveCountMax"', '/etc/ssh/sshd_config')
    if 'ClientAliveInterval 300' in ret1 and 'ClientAliveCountMax 0' in ret2:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_2_13():
    '''
    Restricting which users can remotely access the system via SSH will help
    ensure that only authorized users access the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_13
    '''
    benchmark = '6.2.13 Limit access via SSH (Scored)'

    ret1 = _grep('"^AllowUsers"', '/etc/ssh/sshd_config')
    ret2 = _grep('"^AllowGroups"', '/etc/ssh/sshd_config')
    if ret1 or ret2:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_2_14():
    '''
    Banners are used to warn connecting users of the particular site's policy
    regarding connection. Consult with your legal department for the appropriate
    warning banner for your site.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_2_14
    '''
    benchmark = '6.2.14 Set SSH Banner (Scored)'

    ret = _grep('"^Banner"', '/etc/ssh/sshd_config')
    if ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_3_1():
    '''
    The SHA-512 algorithm provides much stronger hashing than MD5, thus
    providing additional protection to the system by increasing the level of effort
    for an attacker to successfully determine passwords.  Note that these change
    only apply to accounts configured on the local system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_3_1
    '''
    benchmark = '6.3.1 Upgrade password hashing algorithm to SHA-512 (Scored)'

    ret = _grep('"^ENCRYPT_METHOD"', '/etc/login.defs')
    if 'SHA512' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_3_2():
    '''
    Strong passwords protect systems from being hacked through brute force
    methods.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_3_2
    '''
    benchmark = '6.3.2 Set password creation requirement parameters using pam_cracklib (Scored)'

    ret = _grep('"pam_cracklib.so"', '/etc/pam.d/system-auth')
    if ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_3_4():
    '''
    Forcing users not to reuse their past 5 passwords make it less likely that
    an attacker will be able to guess the password.  Note that these change only
    apply to accounts configured on the local system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_3_4
    '''
    benchmark = '6.3.4 Limit password reuise (Scored)'

    ret = _grep('"remember"', '/etc/pam.d/system-auth')
    if ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_6_5():
    '''
    Restricting the use of su, and using sudo in its place, provides system
    administrators better control of the escalation of user privileges to execute
    privileged commands. The sudo utility also provides a better logging and audit
    mechanism, as it can log each command executed via sudo, whereas su can only
    record that a user executed the su program.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_6_5
    '''
    benchmark = '6.5 Restrict access to the su command (Scored)'

    ret = _grep('"pam_wheel.so"', '/etc/pam.d/su')
    if ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_7_1_1():
    '''
    The window of opportunity for an attacker to leverage compromised
    credentials or successfully compromise credentials via an online brute force
    attack is limited by the age of the password. Therefore, reducing the maximum
    age of a password also reduces an an attacker's window of opportunity.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_7_1_1
    '''
    benchmark = '7.1.1 Set password expiration days (Scored)'

    ret = _grep('"PASS_MAX_DAYS"', '/etc/login.defs')
    if '90' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_7_1_2():
    '''
    By restricting the frequency of password changes, an administrator can
    prevent users from repeatedly changing their password in an attempt to
    circumvent password reuse controls.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_7_1_2
    '''
    benchmark = '7.1.2 Set password change minimum number of days (Scored)'

    ret = _grep('"PASS_MIN_DAYS"', '/etc/login.defs')
    if '7' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_7_1_3():
    '''
    Providing an advance warning that a password will be expiring gives users
    time to think of a secure password. Users caught unaware may choose a simple
    password or write it down where it may be discovered

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_7_1_3
    '''
    benchmark = '7.1.3 Set password expiring warning days (Scored)'

    ret = _grep('"PASS_WARN_AGE"', '/etc/login.defs')
    if '7' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_7_2():
    '''
    It is important to make sure that accounts that are not being used by
    regular users are locked to prevent them from being used to provide an
    interactive shell. By default, CentOS sets the password field for these
    accounts to an invalid string, but it is also recommended that the shell field
    in the password file be set to /sbin/nologin. This prevents the account from
    potentially being used to run any commands

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_7_2
    '''
    benchmark = '7.2 Disable system accounts (Scored)'
    cmd = "egrep -v '^\+' /etc/passwd | awk -F: '($1!='root' && $1!='sync' && $1!='shutdown' && $1!='halt' && $3<500 && $7!='/sbin/nologin') {print}'"
    ret = __salt__['cmd.run'](cmd, python_shell=True)
    if not ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_7_3():
    '''
    Using GID 0 for the root account helps prevent root-owned files from
    accidentally becoming accessible to non-privileged users.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_7_3
    '''
    benchmark = '7.3 Set default group for root account (Scored)'

    cmd = 'getent passwd root'
    ret = __salt__['cmd.run'](cmd, python_shell=False)
    if '0:0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_7_4():
    '''
    Setting a very secure default value for umask ensures that users make a
    conscious choice about their file permissions. A default umask setting of 077
    causes files and directories created by users to not be readable by any other
    user on the system. A umask of 027 would make files and directories readable by
    users in the same Unix group, while a umask of 022 would make files readable by
    every user on the system.  Note: The directives in this section apply to bash
    and shell. If other shells are supported on the system, it is recommended that
    their configuration files also are checked. 

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_7_4
    '''
    benchmark = '7.4 Set default umask for users (Scored)'

    ret = _grep('"^umask"', '/etc/bashrc')
    if '077' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_7_5():
    '''
    Inactive accounts pose a threat to system security since the users are not
    logging in to notice failed login attempts or other anomalies.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_7_5
    '''
    benchmark = '7.5 Lock inactive user accounts (Scored)'

    ret = _grep('"^INACTIVE"', '/etc/default/useradd')
    if '-1' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Passed'].append(benchmark)
    return CIS


def audit_8_1():
    '''
    Warning messages inform users who are attempting to login to the system of
    their legal status regarding the system and must include the name of the
    organization that owns the system and any monitoring policies that are in
    place. Consult with your organization's legal counsel for the appropriate
    wording for your specific organization.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_8_1
    '''
    benchmark = '8.1 Set warning banner for standard login services (Scored)'

    ret1 = _stat('/etc/motd')
    ret2 = _stat('/etc/issue')
    ret3 = _stat('/etc/issue.net')
    if '600 0 0' in (ret1 and ret2 and ret3):
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_8_2():
    '''
    Displaying OS and patch level information in login banners also has the
    side effect of providing detailed system information to attackers attempting to
    target specific exploits of a system. Authorized users can easily get this
    information by running the "uname -a" command once they have logged in.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_8_2
    '''
    benchmark = '8.2 Remove OS Information from login warning banners (Scored)'

    ret1 = _grep('"(\\v|\\r|\\m|\\s)"', '/etc/issue')
    ret1 = _grep('"(\\v|\\r|\\m|\\s)"', '/etc/motd')
    ret1 = _grep('"(\\v|\\r|\\m|\\s)"', '/etc/issue.net')
    if not (ret1 or ret2 or ret3):
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_1_2():
    '''
    It is critical to ensure that the /etc/passwd file is protected from
    unauthorized write access. Although it is protected by default, the file
    permissions could be changed either inadvertently or through malicious actions.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_1_2
    '''
    benchmark = '9.1.2 Verify permissions on /etc/passwd (Scored)'

    ret = _stat('/etc/passwd')
    if '600' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_1_3():
    '''
    If attackers can gain read access to the /etc/shadow file, they can easily
    run a password cracking program against the hashed password to break it. Other
    security information that is stored in the /etc/shadow file (such as
    expiration) could also be useful to subvert the user accounts.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_1_3
    '''
    benchmark = '9.1.3 Verify permissions on /etc/shadow (Scored)'

    ret = _stat('/etc/shadow')
    if '000' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_1_4():
    '''
    If attackers can gain read access to the /etc/gshadow file, they can easily
    run a password cracking program against the hashed password to break it. Other
    security information that is stored in the /etc/gshadow file (such as
    expiration) could also be useful to subvert the group accounts.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_1_4
    '''
    benchmark = '9.1.4 Verify permissions on /etc/gshadow (Scored)'

    ret = _stat('/etc/gshadow')
    if '000' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_1_5():
    '''
    The /etc/group file needs to be protected from unauthorized changes by
    non-privileged users, but needs to be readable as this information is used with
    many non-privileged programs.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_1_5
    '''
    benchmark = '9.1.5 Verify permissions on /etc/group (Scored)'

    ret = _stat('/etc/group')
    if '644' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_1_6():
    '''
    The /etc/passwd file needs to be protected from unauthorized changes by
    non-priliveged users, but needs to be readable as this information is used with
    many non-privileged programs.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_1_6
    '''
    benchmark = '9.1.6 Verify user/group ownership on /etc/passwd (Scored)'

    ret = _stat('/etc/passwd')
    if '0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_1_7():
    '''
    If attackers can gain read access to the /etc/shadow file, they can easily
    run a password cracking program against the hashed password to break it. Other
    security information that is stored in the /etc/shadow file (such as
    expiration) could also be useful to subvert the user accounts.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_1_7
    '''
    benchmark = '9.1.7 Verify user/group ownership on /etc/shadow (Scored)'

    ret = _stat('/etc/shadow')
    if '0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_1_8():
    '''
    If attackers can gain read access to the /etc/gshadow file, they can easily
    run a password cracking program against the hashed password to break it. Other
    security information that is stored in the /etc/gshadow file (such as
    expiration) could also be useful to subvert the group accounts.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_1_8
    '''
    benchmark = '9.1.8 Verify user/group ownership on /etc/gshadow (Scored)'

    ret = _stat('/etc/gshadow')
    if '0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_1_9():
    '''
    Verify User/Group Ownership on /etc/group (Scored)

    The /etc/group file needs to be protected from unauthorized changes by
    non-priliveged users, but needs to be readable as this information is used with
    many non-privileged programs.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_1_9
    '''
    benchmark = '9.1.9 Verify user/group ownership on /etc/group (Scored)'

    ret = _stat('/etc/group')
    if '0 0' in ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_1_11():
    '''
    Find Un-owned Files and Directories (Scored)

    A new user who is assigned the deleted user's user ID or group ID may then
    end up "owning" these files, and thus have more access on the system than was
    intended.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_1_11
    '''
    benchmark = '9.1.11 Find Un-owned Files and Directories (Scored)'

    cmd = "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls"
    ret = __salt__['cmd.run'](cmd, python_shell=True)
    if not ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_1_12():
    '''
    A new user who is assigned the deleted user's user ID or group ID may then
    end up "owning" these files, and thus have more access on the system than was
    intended.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_1_12
    '''
    benchmark = '9.1.12 Find Un-grouped Files and Directories (Scored)'

    cmd = "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls"
    ret = __salt__['cmd.run'](cmd, python_shell=True)
    if not ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_2_1():
    '''
    All accounts must have passwords or be locked to prevent the account from
    being used by an unauthorized user.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_2_1
    '''
    benchmark = '9.2.1 Ensure password fields are not emply (Scored)'

    cmd = "/bin/awk -F: '($2 == \"\" ) { print $1 \" does not have a password \"}' /etc/shadow"
    ret = __salt__['cmd.run'](cmd, python_shell=False)
    if not ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_2_2():
    '''
    These entries may provide an avenue for attackers to gain privileged access
    on the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_2_2
    '''
    benchmark = '9.2.2 Verify no legacy "+" entries exist in /etc/passwd file (Scored)'

    ret = _grep('"^+:"', '/etc/passwd')
    if not ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_2_3():
    '''
    These entries may provide an avenue for attackers to gain privileged access
    on the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_2_3
    '''
    benchmark = '9.2.3 Verify no legacy "+" entries exist in /etc/shadow file (Scored)'

    ret = _grep('"^+:"', '/etc/shadow')
    if not ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_2_4():
    '''
    These entries may provide an avenue for attackers to gain privileged access
    on the system.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_2_4
    '''
    benchmark = '9.2.4 Verify no legacy "+" entries exist in /etc/group file (Scored)'

    ret = _grep('"^+:"', '/etc/group')
    if not ret:
        CIS['Passed'].append(benchmark)
    else:
        CIS['Failed'].append(benchmark)
    return CIS


def audit_9_2_5():
    '''
    This access must be limited to only the default root account and only from
    the system console. Administrative access must be through an unprivileged
    account using an approved mechanism as noted in Item 7.5 Restrict root Login to
    System Console.

    CLI Example:

    .. code-block:: shell

        salt '*' cis.audit_9_2_5
    '''
    benchmark = '9.2.5 Verify No UID 0 Accounts Exist Other Than root (Scored)'

    cmd = "/bin/awk -F: '($3 == 0) { print $1 }' /etc/passwd"
    ret = __salt__['cmd.run'](cmd, python_shell=False)
    if not 'root' in ret:
        CIS['Failed'].append(benchmark)
    else:
        CIS['Passed'].append(benchmark)
    return CIS


def audit(details=False, failed=False, passed=False):
    '''
    Return all the things!
    '''
    CIS['Details']['Hostname'] = __salt__['pillar.get']('cmdb:details:name')
    CIS['Details']['Device Service'] = __salt__['pillar.get']('cmdb:details:device_service')

    audit_1_1_1()
    audit_1_1_2()
    audit_1_1_3()
    audit_1_1_4()
    audit_1_1_5()
    audit_1_1_6()
    audit_1_1_7()
    audit_1_1_8()
    audit_1_1_9()
    audit_1_1_10()
    audit_1_1_14()
    audit_1_1_15()
    audit_1_1_16()
    audit_1_1_17()

    audit_1_2_2()

    audit_1_5_1()
    audit_1_5_2()
    audit_1_5_3()
    audit_1_5_4()
    audit_1_5_5()

    audit_1_6_1()
    audit_1_6_2()
    audit_1_6_3()

    audit_2_1_1() ## 2.1.1 Remove telnet-server (Scored)
    audit_2_1_2() ## 2.1.2 Remove telnet Clients (Scored)
    audit_2_1_3() ## 2.1.3 Remove rsh-server (Scored)
    audit_2_1_4() ## 2.1.4 Remove rsh (Scored)
    audit_2_1_5() ## 2.1.5 Remove NIS Client (Scored)
    audit_2_1_6() ## 2.1.6 Remove NIS Server (Scored)
    audit_2_1_7() ## 2.1.7 Remove tftp (Scored)
    audit_2_1_8() ## 2.1.8 Remove tftp-server (Scored)
    audit_2_1_9() ## 2.1.9 Remove talk (Scored)
    audit_2_1_10() ## 2.1.10 Remove talk-server (Scored)
    audit_2_1_11() ## 2.1.11 Remove xinetd (Scored)
    audit_2_1_12() ## 2.1.12 Disable chargen-dgram (Scored)
    audit_2_1_13() ## 2.1.13 Disable chargen-stream (Scored)
    audit_2_1_14() ## 2.1.14 Disable daytime-dgram (Scored)
    audit_2_1_15() ## 2.1.15 Disable daytime-stream (Scored)
    audit_2_1_16() ## 2.1.16 Disable echo-dgram (Scored)
    audit_2_1_17() ## 2.1.17 Disable echo-stream (Scored)
    audit_2_1_18() ## 2.1.18 Disable tcpmux-server (Scored)

    audit_3_1() ## 3.1 Set Daemon umask (Scored)
    audit_3_2() ## 3.2 Remove X Windows (Scored)
    audit_3_3() ## 3.3 Disable Avahi Server (Scored)
    audit_3_5() ## 3.5 Remove DHCP Server (Scored)
    audit_3_6() ## 3.6 Configure Network Time Protocol (NTP) (Scored)
    audit_3_16() ## 3.16 Configure Mail Transfer Agent for Local-Only Mode (Scored)

    audit_4_1_1() ## 4.1.1 Disable IP Forwarding (Scored)
    audit_4_1_2() ## 4.1.2 Disable Send Packet Redirects (Scored)

    audit_4_2_1() ## 4.2.1 Disable Source Routed Packet Acceptance (Scored)
    audit_4_2_2() ## 4.2.2 Disable ICMP Redirect Acceptance (Scored)
    audit_4_2_4() ## 4.2.4 Log Suspicious Packets (Scored)
    audit_4_2_5() ## 4.2.5 Enable Ignore Broadcast Requests (Scored)
    audit_4_2_6() ## 4.2.6 Enable Bad Error Message Protection (Scored)
    audit_4_2_8() ## 4.2.8 Enable TCP SYN Cookies (Scored)

    audit_4_5_3() ## 4.5.3 Verify Permissions on /etc/hosts.allow (Scored)
    audit_4_5_5() ## 4.5.5 Verify Permissions on /etc/hosts.deny (Scored)

    audit_4_7() ## 4.7 Enable IPtables (Scored)

    audit_5_1_1() ## 5.1.1 Install the rsyslog package (Scored)
    audit_5_1_2() ## 5.1.2 Activate the rsyslog Service (Scored)
    audit_5_1_5() ## 5.1.5 Configure rsyslog to Send Logs to a Remote Log Host (Scored)

    audit_6_1_1() ## 6.1.1 Enable anacron Daemon (Scored)
    audit_6_1_2() ## 6.1.2 Enable crond Daemon (Scored)
    audit_6_1_3() ## 6.1.3 Set User/Group Owner and Permission on /etc/anacrontab (Scored)
    audit_6_1_4() ## 6.1.4 Set User/Group Owner and Permission on /etc/crontab (Scored)
    audit_6_1_5() ## 6.1.5 Set User/Group Owner and Permission on /etc/cron.hourly (Scored)
    audit_6_1_6() ## 6.1.6 Set User/Group Owner and Permission on /etc/cron.daily (Scored)
    audit_6_1_7() ## 6.1.7 Set User/Group Owner and Permission on /etc/cron.weekly (Scored)
    audit_6_1_8() ## 6.1.8 Set User/Group Owner and Permission on /etc/cron.monthly (Scored)
    audit_6_1_9() ## 6.1.9 Set User/Group Owner and Permission on /etc/cron.d (Scored)
    audit_6_1_10() ## 6.1.10 Restrict at Daemon (Scored)
    audit_6_1_11() ## 6.1.11 Restrict at/cron to Authorized Users (Scored)

    audit_6_2_1() ## 6.2.1 Set SSH Protocol to 2 (Scored)
    audit_6_2_2() ## 6.2.2 Set LogLevel to INFO (Scored)
    audit_6_2_3() ## 6.2.3 Set Permissions on /etc/ssh/sshd_config (Scored)
    audit_6_2_4() ## 6.2.4 Disable SSH X11 Forwarding (Scored)
    audit_6_2_5() ## 6.2.5 Set SSH MaxAuthTries to 4 or Less (Scored)
    audit_6_2_6() ## 6.2.6 Set SSH IgnoreRhosts to Yes (Scored)
    audit_6_2_7() ## 6.2.7 Set SSH HostbasedAuthentication to No (Scored)
    audit_6_2_8() ## 6.2.8 Disable SSH Root Login (Scored)
    audit_6_2_9() ## 6.2.9 Set SSH PermitEmptyPasswords to No (Scored)
    audit_6_2_10() ## 6.2.10 Do Not Allow Users to Set Environment Options (Scored)
    audit_6_2_11() ## 6.2.11 Use Only Approved Cipher in Counter Mode (Scored)
    audit_6_2_12() ## 6.2.12 Set Idle Timeout Interval for User Login (Scored)
    audit_6_2_13() ## 6.2.13 Limit Access via SSH (Scored)
    audit_6_2_14() ## 6.2.14 Set SSH Banner (Scored)

    audit_6_3_1() ## 6.3.1 Upgrade Password Hashing Algorithm to SHA-512 (Scored)
    audit_6_3_2() ## 6.3.2 Set Password Creation Requirement Parameters Using pam_cracklib (Scored)
    audit_6_3_4() ## 6.3.4 Limit Password Reuse (Scored)

    audit_6_5() ## 6.5 Restrict Access to the su Command (Scored)

    audit_7_1_1() ## 7.1.1 Set Password Expiration Days (Scored)
    audit_7_1_2() ## 7.1.2 Set Password Change Minimum Number of Days (Scored)
    audit_7_1_3() ## 7.1.3 Set Password Expiring Warning Days (Scored)
    audit_7_2() ## 7.2 Disable System Accounts (Scored)
    audit_7_3() ## 7.3 Set Default Group for root Account (Scored)
    audit_7_4() ## 7.4 Set Default umask for Users (Scored)
    audit_7_5() ## 7.5 Lock Inactive User Accounts (Scored)

    audit_8_1() ## 8.1 Set Warning Banner for Standard Login Services (Scored)
    audit_8_2() ## 8.2 Remove OS Information from Login Warning Banners (Scored)

    audit_9_1_2()
    audit_9_1_3()
    audit_9_1_4()
    audit_9_1_5()
    audit_9_1_6()
    audit_9_1_7()
    audit_9_1_8()
    audit_9_1_9() ## 9.1.9 Verify User/Group Ownership on /etc/group (Scored)
    audit_9_1_11()
    audit_9_1_12()

    audit_9_2_1()
    audit_9_2_2()
    audit_9_2_3()
    audit_9_2_4()
    audit_9_2_5()

    for benchmark in CIS['Passed']:
        CIS['Totals']['Pass'] += 1

    for benchmark in CIS['Failed']:
        CIS['Totals']['Fail'] += 1

    if details:
        return CIS
    else:
        return CIS['Totals']

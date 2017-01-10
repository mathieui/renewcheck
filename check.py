#!/usr/bin/env python3
"""
Simple script that checks for expiring certificates. Outputs the
certificates requiring renewal before the time limit given
(default: 30 days).

Works remotely using openssl s_client and locally by having access to
the certificate files.

Requires: python 3.5+, openssl
"""

import enum
import logging
import subprocess

from datetime import datetime, timedelta
from typing import List, Union, IO, Any

DAYS = 30

LOG_FMT = '%(levelname)s: %(message)s'
logging.basicConfig(format=LOG_FMT)
log = logging.getLogger('Cert check')

DOMAIN_CERT_FORMAT = (
    '\033[32;1m%(protocol)s\033[31m cert for \033[0m%(domain)s\033[31;1m '
    'expires in \033[0m\033[41;1m%(days)s DAYS\033[0m'
)

FILE_CERT_FORMAT = (
    '\033[36;1mFILE\033[31m cert \033[0m%(filename)s\033[31;1m expires'
    ' in \033[0m\033[41;1m%(days)s DAYS\033[0m'
)

class ConnectFailure(Exception):
    """Connection failure from openssl"""
class ParseFailure(Exception):
    """Parsing the cert failed"""
class BadProtocolFormat(Exception):
    """the protocol in "protocol:host" line is unknown"""

class Protocol(enum.Enum):
    """Enum of the different protocol/types of certs"""
    HTTPS = 443
    XMPP = 5269
    FILE = -1

    @classmethod
    def get(cls, protocol: str):
        try:
            return getattr(cls, protocol.upper())
        except AttributeError:
            raise BadProtocolFormat(protocol)

class Cert:
    """Container class for cert info"""
    def __init__(self, protocol: Protocol, date: Union[datetime, None]) -> None:
        self.protocol = protocol
        self.date = date

    def has_date(self) -> bool:
        """Check if the expiration date has been fetched"""
        return self.date is not None

    def print(self, days: int):
        """Display a line about the cert"""
        raise NotImplementedError

    def check(self) -> datetime:
        """Check the expiration date of the certificate"""
        raise NotImplementedError


class DomainCert(Cert):
    """Cert fetched/to fetch from the network"""
    __slots__ = ['protocol', 'host', 'date']
    def __init__(self, protocol: Protocol, host: str, date: Union[datetime, None]=None) -> None:
        Cert.__init__(self, protocol, date)
        self.host = host

    def __repr__(self):
        return 'DomainCert(%s, %s, %s)' % (self.protocol.name, self.host, self.date)

    def print(self, days):
        print(DOMAIN_CERT_FORMAT % {
            'protocol': self.protocol.name,
            'domain': self.host,
            'days': days,
            })

    def check(self):
        if self.protocol == Protocol.HTTPS:
            return get_https(self.host)
        elif self.protocol == Protocol.XMPP:
            return get_xmpp(self.host)


class FileCert(Cert):
    """Cert from the filesystem"""
    __slots__ = ['protocol', 'date', 'filename', 'handle']
    def __init__(self, handle: IO[Any], date: Union[datetime, None]=None) -> None:
        Cert.__init__(self, Protocol.FILE, date)
        self.handle = handle
        self.filename = handle.name

    def __repr__(self):
        return 'FileCert(%s, %s)' % (self.filename, self.date)

    def print(self, days):
        print(FILE_CERT_FORMAT % {
            'filename': self.filename,
            'days': days,
            })

    def check(self):
        return get_date_from_handle(self.handle)


def strip_date(date: bytes) -> datetime:
    """sanitize the output of openssl into a datetime"""
    date_str = date.decode().strip().replace('notAfter=', '')
    time = datetime.strptime(date_str, '%b %d %X %Y %Z')
    return time

def get_date_from_handle(handle: IO[Any]) -> datetime:
    """Read a cert from filesystem and get its expiration date"""
    proc = subprocess.Popen(['openssl', 'x509', '-noout', '-enddate'],
                            stdin=handle, stdout=subprocess.PIPE)
    if proc.wait() != 0:
        raise ParseFailure(handle.name)
    proc.terminate()
    res = proc.communicate()[0]
    return strip_date(res)

def get_date_from_network(host: str, port: int, extra: List[str]=[]) -> datetime:
    """
        Read a cert from network and get its expiration date
        Subprocess usage is a mess.
    """
    conn = 'openssl s_client -connect'.split()
    conn.append('%s:%s' % (host, port))
    conn += extra
    proc1 = subprocess.Popen(conn, stdin=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)
    if proc1.wait() != 0:
        raise ConnectFailure('%s:%s' % (host, port))
    proc2 = subprocess.Popen(['openssl', 'x509', '-noout', '-enddate'],
                             stdin=proc1.stdout, stdout=subprocess.PIPE)
    if proc2.wait() != 0:
        raise ParseFailure('%s:%s' % (host, port))
    proc1.terminate()
    proc2.terminate()
    res = proc2.communicate()[0]
    return strip_date(res)

def get_xmpp(host: str) -> datetime:
    return get_date_from_network(host, 5269, extra=['-starttls', 'xmpp'])

def get_https(host: str) -> datetime:
    return get_date_from_network(host, 443)

def expires_soon(date: datetime) -> bool:
    soon = datetime.now() + timedelta(days=DAYS)
    return date < soon

def print_expiring(to_expire: List[Cert]):
    for rec in sorted(to_expire, key=lambda x: x.protocol.value):
        if rec.has_date():
            delta = rec.date - datetime.now()
            rec.print(delta.days)

def check_expiration(certs: List[Cert], print_all: bool=False) -> int:
    to_expire = []
    for rec in certs:
        log.debug("Trying to get the expiration date for %s", rec)
        try:
            date = rec.check()
            rec.date = date
            if expires_soon(date):
                to_expire.append(rec)
        except ConnectFailure as exc:
            log.error('Error fetching data for %s', exc.args[0])
        except ParseFailure as exc:
            log.error('Error parsing cert %s', exc.args[0])
    if print_all:
        print_expiring(certs)
    elif to_expire:
        print_expiring(to_expire)
        return 1
    return 0

def build_handle_list(paths_files: List[IO[Any]], paths: List[IO[Any]]) -> List[Cert]:
    """Build the list of certs to read from the filesystem"""
    files = [] # type: List[Cert]
    for handle in paths_files:
        for filename in handle.read().splitlines():
            filename = filename.strip()
            try:
                files.append(FileCert(handle=open(filename, 'r')))
            except OSError:
                log.error('Unable to open file: %s', filename)
    for handle in paths:
        files.append(FileCert(handle))
    return files

def build_domain_list(domains_files: List[IO[Any]], domain_list: List[str]) -> List[Cert]:
    """Build the list of certs to fetch from the network"""
    raw_domains = [] # type: List[str]
    domains = [] # type: List[Cert]
    for handle in domains_files:
        raw_domains += handle.read().splitlines()
        handle.close()
    raw_domains += domain_list
    for line in raw_domains:
        if line.strip() and ':' in line:
            protocol, host = line.split(':', 1)
            try:
                domains.append(DomainCert(Protocol.get(protocol), host))
            except BadProtocolFormat as exc:
                log.error("Unknown protocol: %s", exc.args[0])
    return domains

def main():
    import argparse
    parser = argparse.ArgumentParser(description=(
        'Tool to check for certificate expiration.\n'
        'Returns 1 if a certificate expires below the time limit'
        ' (default: 30 days).'))
    parser.add_argument('--domains-file', '-df', action='append',
                        type=argparse.FileType('r'), default=[],
                        help='File containg a list of protocol:host lines.')
    parser.add_argument('--domain', '-d', type=str, action='append', default=[],
                        help='protocol:host description')
    parser.add_argument('--paths-file', '-pf', action='append',
                        type=argparse.FileType('r'), default=[],
                        help='File containing a list of certificate paths')
    parser.add_argument('--path', '-p', type=argparse.FileType('r'),
                        action='append', default=[],
                        help='Path to a certificate to check')
    parser.add_argument('--print-all', '-a', action='store_true',
                        default=False, help=('Print all expiration dates, '
                            'even if the certificate is not expiring'))
    parser.add_argument('--min-days', '-m', type=int, default=30,
                        help='Minimal number of days before expiration')
    parser.add_argument('--return-true', '-t', action='store_true',
                        default=False, help='Always return 0.')
    namespace = parser.parse_args()
    files = build_handle_list(namespace.paths_file, namespace.path)
    domains = build_domain_list(namespace.domains_file, namespace.domain)
    global DAYS
    DAYS = namespace.min_days
    if namespace.return_true:
        check_expiration(domains + files, namespace.print_all)
        exit(0)
    else:
        exit(check_expiration(domains + files, namespace.print_all))

if __name__ == '__main__':
    main()

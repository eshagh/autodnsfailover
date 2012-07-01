#!/usr/bin/env python

import errno
import httplib
import os
import select
import signal
import suds
import time
import urllib
import zerigodns
#import route53


# This should probably by named "dynectsession" instead.
class session(object):

    def __init__(self, config):
        self.config = config
        
    def __enter__(self):
        self.client = suds.client.Client(self.config.base_url)
        self.token = None
        self.token = self.call('SessionLogin',
                               customer_name = self.config.customer_name,
                               user_name = self.config.user_name,
                               password = self.config.password).token
        return self

    def call(self, method_name, **parameters):
        parameters['token'] = self.token
        # Some methods do not need the zone parameter.
        if method_name not in ['GetJob']:
            parameters['zone'] = self.config.zone
        parameters['fault_incompat'] = 1
        response = getattr(self.client.service, method_name)(**parameters)
        # GetJob requests are special; the real response is nested
        if method_name == 'GetJob' and response.status == 'success':
            response = response.data
        # Now proceed with regular handling
        if response.status == 'incomplete':
            # Retry!
            return self.call('GetJob', job_id=response.job_id)
        if response.status == 'success':
            if 'data' in response:
                return response.data
            else:
                return None
        if response.status == 'failure':
            for msg in response.msgs:
                # Translate NOT_FOUND errors into silent errors,
                # instead of raising an exception.
                if 'err_cd' in msg and msg.err_cd == 'NOT_FOUND':
                    return None
        # If we reach that point, we are in trouble; raise an exception.
        raise ValueError(str(response))

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None: # all went well, try to logout cleanly
            self.call('SessionLogout')
        return False # propagate any exception


class DynectDns(object):
    """
    Updates a DNS zone hosted by DynECT (http://dyn.com/dns/).
    """
    def __init__(self, config):
        for k,v in config.items():
            setattr(self, k, v)

    def addARecord(self, fqdn, a):
        with session(self) as s:
            s.call('CreateARecord',
                   fqdn = fqdn,
                   rdata = dict(address=a))
            s.call('PublishZone')
            
    def delARecord(self, fqdn, a):
        with session(self) as s:
            try:
                records = s.call('GetARecords',
                                 fqdn = fqdn)
            except ValueError, AttributeError:
                return
            for r in records:
                if r.rdata.address == a:
                    s.call('DeleteOneARecord',
                           fqdn = fqdn,
                           record_id = r.record_id)
            s.call('PublishZone')

    def getARecords(self, fqdn):
        with session(self) as s:
            records = s.call('GetARecords',
                             fqdn = fqdn)
            if records:
                return [r.rdata.address for r in records]
            else:
                return []


class ZerigoDns(object):
    """
    Updates a DNS zone hosted by Zerigo (http://www.zerigo.com/managed-dns).
    Note that this code reloads the whole zone each time. This is clearly
    sub-optimal, but keep in mind that we need to make sure that we always
    see the latest version of the zone.
    """
    def __init__(self, user, key, zone, notes=None, ttl=60):
        self.user = user
        self.key = key
        self.zone = zone
        self.notes = notes
        self.ttl = ttl
        
    @property
    def _zone(self):
        return zerigodns.NSZone(self.user, self.key).find_by_domain(self.zone)

    def _hostname(self, fqdn):
        zone = '.' + self.zone
        assert fqdn.endswith(zone)
        return fqdn[:-len(zone)]
    
    def getARecords(self, fqdn):
        hostname = self._hostname(fqdn)
        try:
            hosts = self._zone.find_by_hostname(hostname)
        except zerigodns.api.ZerigoNotFound:
            hosts = []
        return [h.data
                for h in hosts
                if h.hostname==hostname and h.host_type=='A']

    def addARecord(self, fqdn, a):
        hostname = self._hostname(fqdn)
        self._zone.create_host(dict(hostname=hostname,
                                    ttl=self.ttl,
                                    notes=self.notes,
                                    host_type='A',
                                    data=a))

    def delARecord(self, fqdn, a):
        hostname = self._hostname(fqdn)
        for host in self._zone.find_by_hostname(hostname):
            try:
                if host.host_type == 'A' and host.data == a:
                    host.destroy()
            except zerigodns.ZerigoNotFound:
                pass


class WhatIsMyAddr(object):
    """
    Find our local IP address by querying a remote site. The site should
    just return the IP address by itself.
    """
    def __init__(self, url='http://myip.enix.org/REMOTE_ADDR'):
        self.url = url

    def getOwnAddr(self):
        return urllib.urlopen(self.url).read()


class HttpCheck(object):
    """
    Check that a given HTTP test request can be done correctly.
    """
    def __init__(self, method='GET', url='/', body=None, headers={},
                 port=None, useHttps=False, validStatusCodes=[200,302]):
        self.method = method
        self.url = url
        self.body = body
        self.headers = headers
        if not port:
            port = 80 if not useHttps else 443
        self.port = port
        self.useHttps = useHttps
        self.validStatusCodes = validStatusCodes

    def check(self, ipaddr):
        if self.useHttps:
            connection = httplib.HTTPSConnection(ipaddr, self.port)
        else:
            connection = httplib.HTTPConnection(ipaddr, self.port)

        try:
            connection.request(self.method, self.url, self.body, self.headers)
            response = connection.getresponse()
            return response.status in self.validStatusCodes
        except:
            return False


class TickTimer(object):
    """
    Schedule a check to be executed every *interval* seconds.
    If the check has not returned after *timeout* seconds, kill it.
    The *timeout* is fixed.
    """

    def __init__(self, interval, timeout, retry):
        self.interval = interval
        self.timeout = timeout
        self.retry = retry
        self.last = 0

    def getNextCheckTime(self):
        # Initialization case
        if self.last == 0:
            # Add one second to make sure that the first check is not
            # scheduled in the past
            self.last = time.time() + 1
            return self.last
        # Compute the timestamp of the next check
        self.last += self.interval
        # If we're already late, offset our clock
        if self.last < time.time():
            self.last = time.time()
        return self.last

    def getCheckTimeout(self):
        return self.timeout

    def getRetry(self):
        return self.retry


def boundedCheck(target, check, timer, logger):
    """
    Execute the given *check* on the given *target* (*target* should be an
    IP address). The *timer* is used to retrieve the timeout, and useful
    information will be sent using the *logger*.

    This function will fork(), and the check will be executed in the child
    process. The parent process will wait for the child process, and kill
    it if it did not answer within the timeout specified by the *timer*
    implementation.
    """
    timeout = timer.getCheckTimeout()
    deadline = time.time() + timeout
    logger.debug('starting check {0} on {1}, timeout={2}'
                 .format(check, target, timeout))
    # Use self-pipe trick: setup a SIGCHLD handler to write 1 byte to a pipe
    # (and select() on that pipe)
    pipe = os.pipe()
    def sigchld(sig, frame):
        try:
            os.write(pipe[1], ' ')
        except:
            pass
    signal.signal(signal.SIGCHLD, sigchld)
    pid = os.fork()
    if pid:
        # parent process: wait for the child
        while time.time() < deadline:
            timeout = max(0, deadline - time.time())
            try:
                rfds, wfds, efds = select.select([pipe[0]],[],[],timeout)
            except select.error as err:
                if err.args[0] == errno.EINTR:
                    continue
            if rfds:
                # something in the pipe = got a SIGCHLD
                logger.debug('child exited, retrieving its status')
                childpid, status = os.wait()
                logger.debug('child exit status={0}'.format(status))
                retval = (status==0)
            else:
                # timeout
                logger.info('child timeout, killing it')
                os.kill(pid, signal.SIGKILL)
                logger.debug('reaping child process')
                os.wait()
                retval = False
            os.close(pipe[0])
            os.close(pipe[1])
            logger.debug('check result is {0}'.format(retval))
            return retval
    else:
        # child process: do the check
        try:
            if check.check(target):
                exit(0)
            else:
                exit(1)
        except Exception:
            exit(2)
        

def retryBoundedCheck(target, check, timer, logger):
    retry = timer.getRetry()
    failed = 0
    while True:
        if boundedCheck(target, check, timer, logger):
            # Success!
            if failed:
                # If there were previous failures, log them.
                logger.warning('Check failed {0} time(s) before passing.'
                            .format(failed))
            return True
        failed += 1
        if failed >= retry:
            logger.warning('Check failed {0} times. Giving up.'
                        .format(failed))
            return False
        

def run(fqdns, ipaddr, dns, check, timer, logger):
    """
    This is the "main loop". It will repeatedly retrieve our public
    IP address (it does it each time, in case it changed - this can
    happen with EC2 elastic IPs), add it to the DNS, then check
    that the machines pointed by the other DNS records are fine.
    """
    if isinstance(fqdns, basestring):
        fqdns = [fqdns]

    logger.info('autodnsfailover starting')
    ownAddr = None
    while True:
        now = time.time()
        nextCheck = timer.getNextCheckTime()
        if now > nextCheck:
            logger.warning('we are late by {0} seconds'.format(now-nextCheck))
        while time.time() < nextCheck:
            wait = nextCheck - time.time()
            logger.info('waiting {0} seconds before next round of checks'
                        .format(wait))
            time.sleep(wait)
        logger.debug('getting own addr')
        newOwnAddr = ipaddr.getOwnAddr()
        logger.debug('my own addr = {0}'.format(newOwnAddr))
        if ownAddr != newOwnAddr:
            ownAddr = newOwnAddr
            logger.info('my IP address seems to be {0}'.format(ownAddr))
        logger.debug('doing self-check')
        if not retryBoundedCheck(ownAddr, check, timer, logger):
            logger.critical('self-check failed; waiting 60s and exitting')
            # Don't restart immediately, to avoid a burst of error messages
            time.sleep(60)
            exit(-1)
        logger.debug('self-check passed')
        for fqdn in fqdns:
            logger.debug('getting DNS records')
            records = dns.getARecords(fqdn)
            logger.debug('DNS records: {0}'.format(records))
            if ownAddr not in records:
                logger.info('adding myself ({0}) into DNS'.format(ownAddr))
                dns.addARecord(fqdn, ownAddr)
                logger.warning('added myself ({0}) into DNS'.format(ownAddr))
            logger.debug('checking other peers')
            # Make sure that all peers check each others in the same order
            # (to avoid a race condition where all peers could be removed
            # simultaneously if something is wrong in the check logic itself)
            for otherAddr in sorted(records):
                if not retryBoundedCheck(otherAddr, check, timer, logger):
                    if len(records)<2:
                        logger.error('peer {0} seems dead, but it will not '
                                     'be removed since it is the last peer'
                                     .format(otherAddr))
                    else:
                        logger.error('peer {0} seems dead, removing it from DNS '
                                     .format(otherAddr))
                        dns.delARecord(fqdn, otherAddr)
                        # Only remove one peer at a time; then force a self-check
                        break
                else:
                    logger.debug('peer {0} seems alive'.format(otherAddr))


"""
fs.sftpfs
=========

**Currently only avaiable on Python2 due to paramiko not being available for Python3**

Filesystem accessing an SFTP server (via paramiko)

"""
import sys
if 'gevent.monkey' in sys.modules:
    from gevent import queue as Queue
    from gevent import sleep
else:
    import Queue
    from time import sleep

    class Timeout(Exception):
        """dummy Timeout - not used by python"""
        pass
    Queue.Timeout = Timeout

import contextlib

import datetime
import stat as statinfo
import os
import paramiko
from getpass import getuser

from fs.base import *
from fs.path import *
from fs.errors import *
from fs.utils import isdir, isfile

class WrongHostKeyError(RemoteConnectionError):
    pass

class NoConnectionError(RemoteConnectionError):
    """Unable to create a new connection - pool exhausted"""
    pass

if not hasattr(paramiko.SFTPFile, "__enter__"):
    paramiko.SFTPFile.__enter__ = lambda self: self
    paramiko.SFTPFile.__exit__ = lambda self,et,ev,tb: self.close() and False


class SFTPFS(FS):
    """A filesystem stored on a remote SFTP server.

    This is basically a compatibility wrapper for the excellent SFTPClient
    class in the paramiko module.

    """

    _meta = { 'thread_safe' : True,
              'virtual': False,
              'read_only' : False,
              'unicode_paths' : True,
              'case_insensitive_paths' : False,
              'network' : True,
              'atomic.move' : True,
              'atomic.copy' : True,
              'atomic.makedir' : True,
              'atomic.rename' : True,
              'atomic.setcontents' : False
              }

    def __init__(self,
                 connection,
                 root_path="/",
                 encoding=None,
                 hostkey=None,
                 username='',
                 password=None,
                 pkey=None,
                 agent_auth=True,
                 no_auth=False,
                 look_for_keys=True,
                 max_pool_size=0):
        """SFTPFS constructor.

        The only required argument is 'connection', which must be something
        from which we can construct a paramiko.SFTPClient object.  Possible
        values include:

            * a hostname string
            * a (hostname,port) tuple
            * a paramiko.Transport instance
            * a paramiko.Channel instance in "sftp" mode

        The keyword argument 'root_path' specifies the root directory on the
        remote machine - access to files outside this root will be prevented.

        :param connection: a connection string
        :param root_path: The root path to open
        :param encoding: String encoding of paths (defaults to UTF-8)
        :param hostkey: the host key expected from the server or None if you don't require server validation
        :param username: Name of SFTP user
        :param password: Password for SFTP user
        :param pkey: Public key
        :param agent_auth: attempt to authorize with the user's public keys
        :param no_auth: attempt to log in without any kind of authorization
        :param look_for_keys: Look for keys in the same locations as ssh,
            if other authentication is not succesful
        :param max_pool_size: <=0 ==> infinite pool (unless using gevent, where
            ``Queue(0)`` is a channel, that is, its :meth:`put` method always blocks until the
            item is delivered. When pool is exhausted a NoConnectionError will be raised.

        """

        credentials = dict(username=username,
                           password=password,
                           pkey=pkey)
        self.credentials = credentials

        if encoding is None:
            encoding = "utf8"
        self.encoding = encoding
        self.closed = False
        self._owns_transport = False
        self._credentials = credentials
        self._transport = None
        self._client = None

        self.hostname = None
        if isinstance(connection, basestring):
            self.hostname = connection
        elif isinstance(connection, tuple):
            self.hostname = '%s:%s' % connection

        super(SFTPFS, self).__init__()
        self.root_path = abspath(normpath(root_path))

        max_pool_size = max(max_pool_size, 0)
        self.pool = Queue.Queue(maxsize=max_pool_size)
        self.pool_count = 0

        if isinstance(connection,paramiko.Channel):
            self._transport = None
            self._client = paramiko.SFTPClient(connection)
        else:
            if not isinstance(connection,paramiko.Transport):
                connection = paramiko.Transport(connection)
                connection.daemon = True
                self._owns_transport = True

        if hostkey is not None:
            key = self.get_remote_server_key()
            if hostkey != key:
                raise WrongHostKeyError('Host keys do not match')

        connection.start_client()

        if not connection.is_active():
            raise RemoteConnectionError(msg='Unable to connect')

        if no_auth:
            try:
                connection.auth_none('')
            except paramiko.SSHException:
                pass

        elif not connection.is_authenticated():
            if not username:
                username = getuser()
            try:
                if pkey:
                    connection.auth_publickey(username, pkey)

                if not connection.is_authenticated() and password:
                    connection.auth_password(username, password)

                if agent_auth and not connection.is_authenticated():
                    self._agent_auth(connection, username)

                if look_for_keys and not connection.is_authenticated():
                    self._userkeys_auth(connection, username, password)

                if not connection.is_authenticated():
                    try:
                        connection.auth_none(username)
                    except paramiko.BadAuthenticationType, e:
                        self.close()
                        allowed = ', '.join(e.allowed_types)
                        raise RemoteConnectionError(msg='no auth - server requires one of the following: %s' % allowed, details=e)

                if not connection.is_authenticated():
                    self.close()
                    raise RemoteConnectionError(msg='no auth')

            except paramiko.SSHException, e:
                self.close()
                raise RemoteConnectionError(msg='SSH exception (%s)' % str(e), details=e)

        self._transport = connection

    def __unicode__(self):
        return u'<SFTPFS: %s>' % self.desc('/')

    @classmethod
    def _agent_auth(cls, transport, username):
        """
        Attempt to authenticate to the given transport using any of the private
        keys available from an SSH agent.
        """

        agent = paramiko.Agent()
        agent_keys = agent.get_keys()
        if not agent_keys:
            return None
        for key in agent_keys:
            try:
                transport.auth_publickey(username, key)
                return key
            except paramiko.SSHException:
                pass
        return None

    @classmethod
    def _userkeys_auth(cls, transport, username, password):
        """
        Attempt to authenticate to the given transport using any of the private
        keys in the users ~/.ssh and ~/ssh dirs

        Derived from http://www.lag.net/paramiko/docs/paramiko.client-pysrc.html
        """

        keyfiles = []
        rsa_key = os.path.expanduser('~/.ssh/id_rsa')
        dsa_key = os.path.expanduser('~/.ssh/id_dsa')
        if os.path.isfile(rsa_key):
            keyfiles.append((paramiko.rsakey.RSAKey, rsa_key))
        if os.path.isfile(dsa_key):
            keyfiles.append((paramiko.dsskey.DSSKey, dsa_key))
        # look in ~/ssh/ for windows users:
        rsa_key = os.path.expanduser('~/ssh/id_rsa')
        dsa_key = os.path.expanduser('~/ssh/id_dsa')
        if os.path.isfile(rsa_key):
            keyfiles.append((paramiko.rsakey.RSAKey, rsa_key))
        if os.path.isfile(dsa_key):
            keyfiles.append((paramiko.dsskey.DSSKey, dsa_key))

        for pkey_class, filename in keyfiles:
            key = pkey_class.from_private_key_file(filename, password)
            try:
                transport.auth_publickey(username, key)
                return key
            except paramiko.SSHException:
                pass
        return None

    def __del__(self):
        self.close()

    @synchronize
    def __getstate__(self):
        state = super(SFTPFS,self).__getstate__()
        if self._owns_transport:
            state['_transport'] = self._transport.getpeername()
        return state

    def __setstate__(self,state):
        super(SFTPFS, self).__setstate__(state)
        if self._owns_transport:
            self._transport = paramiko.Transport(self._transport)
            self._transport.connect(**self._credentials)

    @property
    @contextlib.contextmanager
    def client(self):
        managed = False
        result = None
        if not self.closed:
            if self._transport is None:
                result = self._client
            else:
                managed = True
                result = self._get_pool_client()
        try:
            yield result
        finally:
            if managed:
                self.pool.put(result)

    @synchronize
    def _get_pool_client(self):
        # get a connection from the pool
        try:
            client  = self.pool.get_nowait()
        except Queue.Empty:
            if not self.pool.maxsize or self.pool_count < self.pool.maxsize:
                self.pool_count += 1
                self.pool.put(paramiko.SFTPClient.from_transport(self._transport))
                client = self.pool.get()
            else:
                retries = 5
                while True:
                    sleep(1.0)
                    try:
                        client = self.pool.get(block=False, timeout=1.0)
                        break
                    except (Queue.Empty, Queue.Timeout):
                        retries -= 1
                        if not retries:
                            raise NoConnectionError(
                                'No available connection in pool. Max '
                                'size:%s, current size:%s' %(
                                    self.pool.maxsize, self.pool.qsize()))

        return client

    @synchronize
    def close(self):
        """Close the connection to the remote server."""
        if not self.closed:
            while True:
                try:
                    client = self.pool.get_nowait()
                    if client:
                        client.get_channel().close()
                except Queue.Empty:
                    break
            if self._owns_transport and self._transport and self._transport.is_active:
                self._transport.close()
            self.closed = True

    def _normpath(self,path):
        if not isinstance(path,unicode):
            path = path.decode(self.encoding)
        npath = pathjoin(self.root_path,relpath(normpath(path)))
        if not isprefix(self.root_path,npath):
            raise PathError(path,msg="Path is outside root: %(path)s")
        return npath

    def getpathurl(self, path, allow_none=False):
        path = self._normpath(path)
        if self.hostname is None:
            if allow_none:
                return None
            raise NoPathURLError(path=path)
        username = self.credentials.get('username', '') or ''
        password = self.credentials.get('password', '') or ''
        credentials = ('%s:%s' % (username, password)).rstrip(':')
        if credentials:
            url = 'sftp://%s@%s%s' % (credentials, self.hostname.rstrip('/'), abspath(path))
        else:
            url = 'sftp://%s%s' % (self.hostname.rstrip('/'), abspath(path))
        return url

    @synchronize
    @convert_os_errors
    def open(self,path,mode="rb",bufsize=-1):
        npath = self._normpath(path)
        if self.isdir(path):
            msg = "that's a directory: %(path)s"
            raise ResourceInvalidError(path,msg=msg)
        #  paramiko implements its own buffering and write-back logic,
        #  so we don't need to use a RemoteFileBuffer here.
        client = self._get_pool_client()
        try:
            f = client.open(npath,mode,bufsize)
        except Exception:
            # release client if any error
            self.pool.put(client)
            raise

        #  Unfortunately it has a broken truncate() method.
        #  TODO: implement this as a wrapper
        old_truncate = f.truncate
        def new_truncate(size=None):
            if size is None:
                size = f.tell()
            return old_truncate(size)
        f.truncate = new_truncate
        # wrap the close to release the client
        old_close = f.close
        def new_close():
            # release client
            self.pool.put(client)
        f.close = new_close
        return f

    @synchronize
    def desc(self, path):
        npath = self._normpath(path)
        if self.hostname:
            return u'sftp://%s%s' % (self.hostname, path)
        else:
            addr, port = self._transport.getpeername()
            with self.client as client:
                return u'sftp://%s:%i%s' % (addr, port, client.normalize(npath))

    @synchronize
    @convert_os_errors
    def exists(self,path):
        if path in ('', '/'):
            return True
        npath = self._normpath(path)
        with self.client as client:
            try:
                client.stat(npath)
            except IOError, e:
                if getattr(e,"errno",None) == 2:
                    return False
                raise
            return True

    @synchronize
    @convert_os_errors
    def isdir(self,path):
        with self.client as client:
            if path in ('', '/'):
                return True
            npath = self._normpath(path)
            try:
                stat = client.stat(npath)
            except IOError, e:
                if getattr(e,"errno",None) == 2:
                    return False
                raise
            return statinfo.S_ISDIR(stat.st_mode)

    @synchronize
    @convert_os_errors
    def isfile(self,path):
        npath = self._normpath(path)
        with self.client as client:
            try:
                stat = client.stat(npath)
            except IOError, e:
                if getattr(e,"errno",None) == 2:
                    return False
                raise
            return statinfo.S_ISREG(stat.st_mode)

    @synchronize
    @convert_os_errors
    def listdir(self,path="./",wildcard=None,full=False,absolute=False,dirs_only=False,files_only=False):
        npath = self._normpath(path)
        with self.client as client:
            try:
                attrs_map = None
                if dirs_only or files_only:
                    attrs = client.listdir_attr(npath)
                    attrs_map = dict((a.filename, a) for a in attrs)
                    paths = list(attrs_map.iterkeys())
                else:
                    paths = client.listdir(npath)
            except IOError, e:
                if getattr(e,"errno",None) == 2:
                    if self.isfile(path):
                        raise ResourceInvalidError(path,msg="Can't list directory contents of a file: %(path)s")
                    raise ResourceNotFoundError(path)
                elif self.isfile(path):
                    raise ResourceInvalidError(path,msg="Can't list directory contents of a file: %(path)s")
                raise

        if attrs_map:
            if dirs_only:
                filter_paths = []
                for apath, attr in attrs_map.iteritems():
                    if isdir(self, path, attr.__dict__):
                        filter_paths.append(apath)
                paths = filter_paths
            elif files_only:
                filter_paths = []
                for apath, attr in attrs_map.iteritems():
                    if isfile(self, apath, attr.__dict__):
                        filter_paths.append(apath)
                paths = filter_paths

        for (i,p) in enumerate(paths):
            if not isinstance(p,unicode):
                paths[i] = p.decode(self.encoding)

        return self._listdir_helper(path, paths, wildcard, full, absolute, False, False)

    @synchronize
    @convert_os_errors
    def listdirinfo(self,path="./",wildcard=None,full=False,absolute=False,dirs_only=False,files_only=False):
        npath = self._normpath(path)
        with self.client as client:
            try:
                attrs = client.listdir_attr(npath)
                attrs_map = dict((a.filename, a) for a in attrs)
                paths = attrs_map.keys()
            except IOError, e:
                if getattr(e,"errno",None) == 2:
                    if self.isfile(path):
                        raise ResourceInvalidError(path,msg="Can't list directory contents of a file: %(path)s")
                    raise ResourceNotFoundError(path)
                elif self.isfile(path):
                    raise ResourceInvalidError(path,msg="Can't list directory contents of a file: %(path)s")
                raise

        if dirs_only:
            filter_paths = []
            for path, attr in attrs_map.iteritems():
                if isdir(self, path, attr.__dict__):
                    filter_paths.append(path)
            paths = filter_paths
        elif files_only:
            filter_paths = []
            for path, attr in attrs_map.iteritems():
                if isfile(self, path, attr.__dict__):
                    filter_paths.append(path)
            paths = filter_paths

        for (i, p) in enumerate(paths):
            if not isinstance(p, unicode):
                paths[i] = p.decode(self.encoding)

        def getinfo(p):
            resourcename = basename(p)
            info = attrs_map.get(resourcename)
            if info is None:
                return self.getinfo(pathjoin(path, p))
            return self._extract_info(info.__dict__)

        return [(p, getinfo(p)) for p in
                    self._listdir_helper(path, paths, wildcard, full, absolute, False, False)]

    @synchronize
    @convert_os_errors
    def makedir(self,path,recursive=False,allow_recreate=False):
        npath = self._normpath(path)
        with self.client as client:
            try:
                client.mkdir(npath)
            except IOError, _e:
                # Error code is unreliable, try to figure out what went wrong
                try:
                    stat = client.stat(npath)
                except IOError:
                    if not self.isdir(dirname(path)):
                        # Parent dir is missing
                        if not recursive:
                            raise ParentDirectoryMissingError(path)
                        self.makedir(dirname(path),recursive=True)
                        self.makedir(path,allow_recreate=allow_recreate)
                    else:
                        # Undetermined error, let the decorator handle it
                        raise
                else:
                    # Destination exists
                    if statinfo.S_ISDIR(stat.st_mode):
                        if not allow_recreate:
                            raise DestinationExistsError(path,msg="Can't create a directory that already exists (try allow_recreate=True): %(path)s")
                    else:
                        raise ResourceInvalidError(path,msg="Can't create directory, there's already a file of that name: %(path)s")

    @synchronize
    @convert_os_errors
    def remove(self,path):
        npath = self._normpath(path)
        with self.client as client:
            try:
                client.remove(npath)
            except IOError, e:
                if getattr(e,"errno",None) == 2:
                    raise ResourceNotFoundError(path)
                elif self.isdir(path):
                    raise ResourceInvalidError(path,msg="Cannot use remove() on a directory: %(path)s")
                raise

    @synchronize
    @convert_os_errors
    def removedir(self,path,recursive=False,force=False):
        npath = self._normpath(path)
        if normpath(path) in ('', '/'):
            raise RemoveRootError(path)
        if force:
            for path2 in self.listdir(path,absolute=True):
                try:
                    self.remove(path2)
                except ResourceInvalidError:
                    self.removedir(path2,force=True)
        if not self.exists(path):
            raise ResourceNotFoundError(path)
        with self.client as client:
            try:
                client.rmdir(npath)
            except IOError, e:
                if getattr(e,"errno",None) == 2:
                    if self.isfile(path):
                        raise ResourceInvalidError(path,msg="Can't use removedir() on a file: %(path)s")
                    raise ResourceNotFoundError(path)

                elif self.listdir(path):
                    raise DirectoryNotEmptyError(path)
                raise
            if recursive:
                try:
                    self.removedir(dirname(path),recursive=True)
                except DirectoryNotEmptyError:
                    pass

    @synchronize
    @convert_os_errors
    def rename(self,src,dst):
        nsrc = self._normpath(src)
        ndst = self._normpath(dst)
        with self.client as client:
            try:
                client.rename(nsrc,ndst)
            except IOError, e:
                if getattr(e,"errno",None) == 2:
                    raise ResourceNotFoundError(src)
                if not self.isdir(dirname(dst)):
                    raise ParentDirectoryMissingError(dst)
                raise

    @synchronize
    @convert_os_errors
    def move(self,src,dst,overwrite=False,chunk_size=16384):
        nsrc = self._normpath(src)
        ndst = self._normpath(dst)
        if overwrite and self.isfile(dst):
            self.remove(dst)
        with self.client as client:
            try:
                client.rename(nsrc,ndst)
            except IOError, e:
                if getattr(e,"errno",None) == 2:
                    raise ResourceNotFoundError(src)
                if self.exists(dst):
                    raise DestinationExistsError(dst)
                if not self.isdir(dirname(dst)):
                    raise ParentDirectoryMissingError(dst,msg="Destination directory does not exist: %(path)s")
                raise

    @synchronize
    @convert_os_errors
    def movedir(self,src,dst,overwrite=False,ignore_errors=False,chunk_size=16384):
        nsrc = self._normpath(src)
        ndst = self._normpath(dst)
        if overwrite and self.isdir(dst):
            self.removedir(dst)
        with self.client as client:
            try:
                client.rename(nsrc,ndst)
            except IOError, e:
                if getattr(e,"errno",None) == 2:
                    raise ResourceNotFoundError(src)
                if self.exists(dst):
                    raise DestinationExistsError(dst)
                if not self.isdir(dirname(dst)):
                    raise ParentDirectoryMissingError(dst,msg="Destination directory does not exist: %(path)s")
                raise

    _info_vars = frozenset('st_size st_uid st_gid st_mode st_atime st_mtime'.split())
    @classmethod
    def _extract_info(cls, stats):
        fromtimestamp = datetime.datetime.fromtimestamp
        info = dict((k, v) for k, v in stats.iteritems() if k in cls._info_vars and not k.startswith('_'))
        info['size'] = info['st_size']
        ct = info.get('st_ctime')
        if ct is not None:
            info['created_time'] = fromtimestamp(ct)
        at = info.get('st_atime')
        if at is not None:
            info['accessed_time'] = fromtimestamp(at)
        mt = info.get('st_mtime')
        if mt is not None:
            info['modified_time'] = fromtimestamp(mt)
        return info

    @synchronize
    @convert_os_errors
    def getinfo(self, path):
        npath = self._normpath(path)
        with self.client as client:
            stats = client.stat(npath)
            info = dict((k, getattr(stats, k)) for k in dir(stats) if not k.startswith('_'))
            info['size'] = info['st_size']
            ct = info.get('st_ctime', None)
            if ct is not None:
                info['created_time'] = datetime.datetime.fromtimestamp(ct)
            at = info.get('st_atime', None)
            if at is not None:
                info['accessed_time'] = datetime.datetime.fromtimestamp(at)
            mt = info.get('st_mtime', None)
            if mt is not None:
                info['modified_time'] = datetime.datetime.fromtimestamp(mt)
            return info

    @synchronize
    @convert_os_errors
    def getsize(self, path):
        npath = self._normpath(path)
        with self.client as client:
            stats = client.stat(npath)
            return stats.st_size

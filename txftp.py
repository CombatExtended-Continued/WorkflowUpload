from twisted.cred.portal import Portal
from twisted.conch.ssh import factory, userauth, connection, keys, session
from twisted.conch.ssh.factory import SSHFactory
from twisted.internet import reactor
from twisted.conch.ssh.keys import Key
from twisted.conch.ssh import session, forwarding, filetransfer
from twisted.conch import checkers

from twisted.python.components import registerAdapter

from twisted.conch.interfaces import IConchUser
from twisted.conch.avatar import ConchUser
from twisted.conch.ssh.channel import SSHChannel
from twisted.conch.ssh.filetransfer import FileTransferServer, implementer, ISFTPServer, ISFTPFile
from twisted.conch.ssh.session import parseRequest_pty_req
from twisted.internet.protocol import Protocol
from twisted.conch.ssh.session import SSHSession, SSHSessionProcessProtocol, wrapProtocol

FXF_READ = 0x00000001
FXF_WRITE = 0x00000002
FXF_APPEND = 0x00000004
FXF_CREAT = 0x00000008
FXF_TRUNC = 0x00000010
FXF_EXCL = 0x00000020
FXF_TEXT = 0x00000040


from twisted.python import log
import sys

from twisted.python.filepath import FilePath

if len(sys.argv) < 7:
    print("Usage: txftp.py <directory> <privateKeyFile> <publicKeyFile> <username> <clientPublicKeyFile> <port>")
    raise SystemExit(1)
log.startLogging(sys.stderr)

port = int(sys.argv[6])
username = sys.argv[4].decode('charmap')


target = FilePath(sys.argv[1])

@implementer(ISFTPFile)
class ServerFile(object):
    def __init__(self, fp, flags):
        self.filePath = fp;
        fm = ''
        if flags & FXF_READ:
            fm += 'r'
        if flags & FXF_WRITE:
            fm += ('+' if fm else 'w')
        if flags & FXF_APPEND:
            fm = 'a'
        if flags & FXF_TRUNC:
            fm = 'w'
        if not (flags & FXF_TEXT):
            fm += 'b'
        
            
        self._handle = fp.open(fm)
    
    def close(self):
        self._handle.close()
        self._handle = None


    def readChunk(self, offset, length):
        self._handle.seek(offset)
        a = self._handle.read(length)
        if a:
            return a
        raise EOFError("")


    def writeChunk(self, offset, data):
        self._handle.seek(offset)
        self._handle.write(data)


    def getAttrs(self):
        return getStats(self.filePath)


    def setAttrs(self, attrs):
        return

def getStats(s):
    import os
    return dict(size=s.getsize(),
                uid=s.getUserID(),
                gid=s.getGroupID(),
                permissions=os.stat(s.path).st_mode,
                atime=s.getatime(),
                mtime=s.getmtime())

    
class DirectoryIterator(object):
    def __init__(self, d: FilePath):
        self._d = d
    def close(self):
        pass

    def __iter__(self):
        for f in self._d.children():
            yield f.basename(), f.basename(), getStats(f)


@implementer(ISFTPServer)
class SSHFileServer(Protocol):
    def __init__(self, parent, avatar):
        print(81)
        super().__init__()
        self._parent = parent
        self.avatar = avatar
    
    def connectionLost(self, reason):
        print( 'Connection lost', reason)

    def gotVersion(self, otherVersion, extData):
        """
        Called when the client sends their version info.

        otherVersion is an integer representing the version of the SFTP
        protocol they are claiming.
        extData is a dictionary of extended_name : extended_data items.
        These items are sent by the client to indicate additional features.

        This method should return a dictionary of extended_name : extended_data
        items.  These items are the additional features (if any) supported
        by the server.
        """
        return {}


    def openFile(self, filename, flags, attrs):
        return ServerFile(target.descendant(filename.decode('charmap').split('/')), flags)


    def removeFile(self, filename):
        target.descendant(filename.decode('charmap').split('/')).remove()


    def renameFile(self, oldpath, newpath):
        target.descendant(oldpath.decode('charmap').split('/')).moveTo(target.descendant(newpath.decode('charmap').split('/')), False)


    def makeDirectory(self, path, attrs):
        target.descendant(path.decode('charmap').split('/')).makedirs()


    def removeDirectory(self, path):
        t = target.descendant(path.decode('charmap').split('/'))
        if t.isdir() and not t.children():
            t.remove()


    def openDirectory(self, path):
        print(140, path)
        return DirectoryIterator(target.descendant(path.decode('charmap').split('/')))
        """
        Open a directory for scanning.

        This method returns an iterable object that has a close() method,
        or a Deferred that is called back with same.

        The close() method is called when the client is finished reading
        from the directory.  At this point, the iterable will no longer
        be used.

        The iterable should return triples of the form (filename,
        longname, attrs) or Deferreds that return the same.  The
        sequence must support __getitem__, but otherwise may be any
        'sequence-like' object.

        filename is the name of the file relative to the directory.
        logname is an expanded format of the filename.  The recommended format
        is:
        -rwxr-xr-x   1 mjos     staff      348911 Mar 25 14:29 t-filexfer
        1234567890 123 12345678 12345678 12345678 123456789012

        The first line is sample output, the second is the length of the field.
        The fields are: permissions, link count, user owner, group owner,
        size in bytes, modification time.

        attrs is a dictionary in the format of the attrs argument to openFile.

        @param path: the directory to open.
        """


    def getAttrs(self, path, followLinks):
        s = target.descendant(path.decode('charmap').split('/'))
        return getStats(s)
        """
        Return the attributes for the given path.

        This method returns a dictionary in the same format as the attrs
        argument to openFile or a Deferred that is called back with same.

        @param path: the path to return attributes for as a string.
        @param followLinks: a boolean.  If it is True, follow symbolic links
        and return attributes for the real path at the base.  If it is False,
        return attributes for the specified path.
        """


    def setAttrs(self, path, attrs):
#        raise NotImplemented()
        """
        Set the attributes for the path.

        This method returns when the attributes are set or a Deferred that is
        called back when they are.

        @param path: the path to set attributes for as a string.
        @param attrs: a dictionary in the same format as the attrs argument to
        L{openFile}.
        """


    def readLink(path):
        return path
        """
        Find the root of a set of symbolic links.

        This method returns the target of the link, or a Deferred that
        returns the same.

        @param path: the path of the symlink to read.
        """


    def makeLink(linkPath, targetPath):
        raise NotImplemented()
        """
        Create a symbolic link.

        This method returns when the link is made, or a Deferred that
        returns the same.

        @param linkPath: the pathname of the symlink as a string.
        @param targetPath: the path of the target of the link as a string.
        """


    def realPath(self, path):
        return path
        """
        Convert any path to an absolute path.

        This method returns the absolute path as a string, or a Deferred
        that returns the same.

        @param path: the path to convert as a string.
        """


    def extendedRequest(extendedName, extendedData):
        raise NotImplementedError()




with open(sys.argv[2]) as privateBlobFile:
    privateBlob = privateBlobFile.read()
    privateKey  = Key.fromString(data=privateBlob)

with open(sys.argv[3]) as publicBlobFile:
    publicBlob = publicBlobFile.read()
    publicKey  = Key.fromString(data=publicBlob)

with open(sys.argv[5]) as clientBlobFile:
    clientBlob = clientBlobFile.read()
    clientKey = Key.fromString(data=clientBlob)

class EchoProtocol(Protocol):
    def connectionMade(self):
        self.transport.write("Echo protocol connected\r\n")

    def dataReceived(self, bytes):
        self.transport.write("echo: " + repr(bytes) + "\r\n")



class SimpleSession(SSHSession):
    name = 'session'
    def requestReceived(self, *args):
        print(248, args)
        return super().requestReceived(*args)
    def __getattr__(self, attr):
        print(attr)
        return super().__getattr__(attr)
    def request_shell(self, data):
        protocol  = EchoProtocol()
        transport = SSHSessionProcessProtocol(self)
        protocol.makeConnection(transport)
        transport.makeConnection(wrapProtocol(protocol))
        self.client = transport
        return True

    def request_subsystem(self, *args):
        print(258, args)
        ret = super().request_subsystem(*args)
        print(ret)
        return ret

    def request_pty_req(self, *args):
        return False

    def request_exec(self, data):
        return False

    def request_window_change(self, *args):
        return

    def request_env(self, *args):
        print(args)
        

    def closed(self):
        print( 'closed')

    def closeReceived(self):
        print( 'closeReceived')

class SimpleUser(ConchUser):
    def dataReceived(self, *args):
        print(282, args)
        return super().dataReceived(*args)

registerAdapter(lambda user: SSHFileServer(None, user), SimpleUser, ISFTPServer)
    
class SimpleRealm(object):
    def requestAvatar(self, avatarId, mind, *interfaces):
        user = SimpleUser()
        user.subsystemLookup.update(
                {b"sftp": filetransfer.FileTransferServer})       
#        user.subsystemLookup[b'sftp'] = SSHFileServer
        user.channelLookup[b'session'] = SimpleSession
        return IConchUser, user, print

factory = SSHFactory()
factory.privateKeys = { b'ssh-rsa': privateKey }
factory.publicKeys  = { b'ssh-rsa': publicKey  }

with open('/etc/ssh/moduli', 'r') as p:
    primes = factory.primes = {}
    for l in p:
        l = l.strip()
        if not l or l[0] == '#':
            continue
        tim, typ, tst, tri, size, gen, mod = l.split()
        size = int(size) + 1
        gen = int(gen)
        mod = int(mod, 16)
        if not size in primes:
            primes[size] = []
        primes[size].append((gen, mod))



    
    
    

        
factory.portal = Portal(SimpleRealm())

factory.portal.registerChecker(checkers.SSHPublicKeyChecker(checkers.InMemorySSHKeyDB({username:[clientKey]})))
print(307)
print(factory.portal.listCredentialsInterfaces())

reactor.listenTCP(port, factory)
reactor.run()

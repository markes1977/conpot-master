# Command Responder (GET/GETNEXT)
# Based on examples from http://pyopc.sourceforge.net/

import logging

from pyopc.entity import config
from pyopc.entity.rfc3413 import context
from pyopc.carrier.asynsock.dgram import udp
from pyopc.entity import engine
from pyopc.smi import builder
import gevent

from conpot.protocols.opc import conpot_cmdrsp
from conpot.protocols.opc.databus_mediator import DatabusMediator
from gevent.server import DatagramServer

logger = logging.getLogger(__name__)


class OPCDispatcher(DatagramServer):
    def __init__(self):
        self.__timerResolution = 0.5

    def registerRecvCbFun(self, recvCbFun, recvId=None):
        self.recvCbFun = recvCbFun

    def handle(self, msg, address):
        try:
            self.recvCbFun(self, self.transportDomain, address, msg)
        except Exception as e:
            logger.info("OPC Exception: %s", e)

    def registerTransport(self, tDomain, transport):
        DatagramServer.__init__(self, transport, self.handle)
        self.transportDomain = tDomain

    def registerTimerCbFun(self, timerCbFun, tickInterval=None):
        pass

    def sendMessage(self, outgoingMessage, transportDomain, transportAddress):
        self.socket.sendto(outgoingMessage, transportAddress)

    def getTimerResolution(self):
        return self.__timerResolution


class CommandResponder(object):
    def __init__(self, host, port, mibpaths):

        self.oid_mapping = {}
        self.databus_mediator = DatabusMediator(self.oid_mapping)
        # mapping between OID and databus keys

        # Create OPC engine
        self.opcEngine = engine.SnmpEngine()

        # path to custom mibs
        mibBuilder = self.opcEngine.msgAndPduDsp.mibInstrumController.mibBuilder
        mibSources = mibBuilder.getMibSources()

        for mibpath in mibpaths:
            mibSources += (builder.DirMibSource(mibpath),)
        mibBuilder.setMibSources(*mibSources)

        # Transport setup
        udp_sock = gevent.socket.socket(gevent.socket.AF_INET, gevent.socket.SOCK_DGRAM)
        udp_sock.setsockopt(gevent.socket.SOL_SOCKET, gevent.socket.SO_BROADCAST, 1)
        udp_sock.bind((host, port))
        self.server_port = udp_sock.getsockname()[1]
        # UDP over IPv4
        self.addSocketTransport(
            self.opcEngine,
            udp.domainName,
            udp_sock
        )

        # OPCv1
        config.addV1System(self.opcEngine, 'public-read', 'public')

        # OPCv3/USM setup
        # user: usr-md5-des, auth: MD5, priv DES
        config.addV3User(
            self.opcEngine, 'usr-md5-des',
            config.usmHMACMD5AuthProtocol, 'authkey1',
            config.usmDESPrivProtocol, 'privkey1'
        )
        # user: usr-sha-none, auth: SHA, priv NONE
        config.addV3User(
            self.opcEngine, 'usr-sha-none',
            config.usmHMACSHAAuthProtocol, 'authkey1'
        )
        # user: usr-sha-aes128, auth: SHA, priv AES/128
        config.addV3User(
            self.opcEngine, 'usr-sha-aes128',
            config.usmHMACSHAAuthProtocol, 'authkey1',
            config.usmAesCfb128Protocol, 'privkey1'
        )

        # Allow full MIB access for each user at VACM
        config.addVacmUser(self.opcEngine, 1, 'public-read', 'noAuthNoPriv',
                           readSubTree=(1, 3, 6, 1, 2, 1), writeSubTree=(1, 3, 6, 1, 2, 1))
        config.addVacmUser(self.opcEngine, 3, 'usr-md5-des', 'authPriv',
                           readSubTree=(1, 3, 6, 1, 2, 1), writeSubTree=(1, 3, 6, 1, 2, 1))
        config.addVacmUser(self.opcEngine, 3, 'usr-sha-none', 'authNoPriv',
                           readSubTree=(1, 3, 6, 1, 2, 1), writeSubTree=(1, 3, 6, 1, 2, 1))
        config.addVacmUser(self.opcEngine, 3, 'usr-sha-aes128', 'authPriv',
                           readSubTree=(1, 3, 6, 1, 2, 1), writeSubTree=(1, 3, 6, 1, 2, 1))

        # Get default OPC context this OPC engine serves
        opcContext = context.SnmpContext(self.opcEngine)

        # Register OPC Applications at the OPC engine for particular OPC context
        self.resp_app_get = conpot_cmdrsp.c_GetCommandResponder(self.opcEngine, opcContext, self.databus_mediator)
        self.resp_app_set = conpot_cmdrsp.c_SetCommandResponder(self.opcEngine, opcContext, self.databus_mediator)
        self.resp_app_next = conpot_cmdrsp.c_NextCommandResponder(self.opcEngine, opcContext, self.databus_mediator)
        self.resp_app_bulk = conpot_cmdrsp.c_BulkCommandResponder(self.opcEngine, opcContext, self.databus_mediator)

    def addSocketTransport(self, opcEngine, transportDomain, transport):
        """Add transport object to socket dispatcher of opcEngine"""
        if not opcEngine.transportDispatcher:
            opcEngine.registerTransportDispatcher(OPCDispatcher())
        opcEngine.transportDispatcher.registerTransport(transportDomain, transport)

    def register(self, mibname, symbolname, instance, value, profile_map_name):
        """Register OID"""
        self.opcEngine.msgAndPduDsp.mibInstrumController.mibBuilder.loadModules(mibname)
        s = self._get_mibSymbol(mibname, symbolname)

        if s:
            self.oid_mapping[s.name+instance] = profile_map_name

            MibScalarInstance, = self.opcEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('OPCv2-SMI',
                                                                                                            'MibScalarInstance')
            x = MibScalarInstance(s.name, instance, s.syntax.clone(value))
            self.opcEngine.msgAndPduDsp.mibInstrumController.mibBuilder.exportSymbols(mibname, x)

            logger.debug('Registered: OID %s Instance %s ASN.1 (%s @ %s) value %s dynrsp.', s.name, instance, s.label, mibname, value)

        else:
            logger.debug('Skipped: OID for symbol %s not found in MIB %s', symbolname, mibname)

    def _get_mibSymbol(self, mibname, symbolname):
        modules = self.opcEngine.msgAndPduDsp.mibInstrumController.mibBuilder.mibSymbols
        if mibname in modules:
            if symbolname in modules[mibname]:
                return modules[mibname][symbolname]

    def has_mib(self, mibname):
        modules = self.opcEngine.msgAndPduDsp.mibInstrumController.mibBuilder.mibSymbols
        return mibname in modules

    def serve_forever(self):
        self.opcEngine.transportDispatcher.serve_forever()

    def stop(self):
        self.opcEngine.transportDispatcher.stop_accepting()


if __name__ == "__main__":
    server = CommandResponder()
    print 'Starting echo server on port 161'
    server.serve_forever()

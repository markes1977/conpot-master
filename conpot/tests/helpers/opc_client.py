# Command Responder (GET/GETNEXT)
# Based on examples from http://pyopc.sourceforge.net/

from pyopc.entity import engine, config
from pyopc.carrier.asynsock.dgram import udp
from pyopc.entity.rfc3413 import cmdgen
from pyopc.proto import rfc1902


class OPCClient(object):
    def __init__(self, host, port):

        # Create OPC engine instance
        self.opcEngine = engine.SnmpEngine()

        # user: usr-sha-aes, auth: SHA, priv AES
        config.addV3User(
            self.opcEngine, 'usr-sha-aes128',
            config.usmHMACSHAAuthProtocol, 'authkey1',
            config.usmAesCfb128Protocol, 'privkey1'
        )
        config.addTargetParams(self.opcEngine, 'my-creds', 'usr-sha-aes128', 'authPriv')

        # Setup transport endpoint and bind it with security settings yielding
        # a target name (choose one entry depending of the transport needed).

        # UDP/IPv4
        config.addSocketTransport(
            self.opcEngine,
            udp.domainName,
            udp.UdpSocketTransport().openClientMode()
        )
        config.addTargetAddr(
            self.opcEngine, 'my-router',
            udp.domainName, (host, port),
            'my-creds'
        )

    # Error/response receiver
    def cbFun(self, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBindTable, cbCtx):
        if errorIndication:
            print(errorIndication)
        elif errorStatus:
            print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBindTable[-1][int(errorIndex) - 1] or '?')
            )
        else:
            for oid, val in varBindTable:
                print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))

    def get_command(self, OID=((1, 3, 6, 1, 2, 1, 1, 1, 0), None), callback=None):
        if not callback:
            callback = self.cbFun
            # Prepare and send a request message
        cmdgen.GetCommandGenerator().sendReq(
            self.opcEngine,
            'my-router',
            (OID,),
            callback,
        )
        self.opcEngine.transportDispatcher.runDispatcher()
        # Run I/O dispatcher which would send pending queries and process responses
        self.opcEngine.transportDispatcher.runDispatcher()

    def set_command(self, OID, callback=None):
        if not callback:
            callback = self.cbFun
        cmdgen.SetCommandGenerator().sendReq(
            self.opcEngine,
            'my-router',
            (OID,),
            callback,
        )
        self.opcEngine.transportDispatcher.runDispatcher()

    def walk_command(self, OID, callback=None):
        if not callback:
            callback = self.cbFun
        cmdgen.NextCommandGenerator().sendReq(
            self.opcEngine,
            'my-router',
            (OID,),
            callback,
        )


if __name__ == "__main__":
    opc_client = OPCClient('127.0.0.1', 161)
    OID = ((1, 3, 6, 1, 2, 1, 1, 1, 0), None)
    opc_client.get_command(OID)

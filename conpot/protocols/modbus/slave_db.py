# modified by Sooky Peter <xsooky00@stud.fit.vutbr.cz>
# Brno University of Technology, Faculty of Information Technology
import struct
from lxml import etree

from modbus_tk.modbus import Databank, DuplicatedKeyError, MissingKeyError, \
                             ModbusInvalidRequestError
from modbus_tk import defines

from conpot.protocols.modbus.slave import MBSlave
import logging

logger = logging.getLogger(__name__)


class SlaveBase(Databank):

    """
    Database keeping track of the slaves.
    """

    def __init__(self, template):
        Databank.__init__(self)
        self.dom = etree.parse(template)

    def add_slave(self, slave_id):
        """
        Add a new slave with the given id
        """
        if (slave_id < 0) or (slave_id > 255):
            raise Exception("Invalid slave id %d" % slave_id)
        if slave_id not in self._slaves:
            self._slaves[slave_id] = MBSlave(slave_id, self.dom)
            return self._slaves[slave_id]
        else:
            raise DuplicatedKeyError("Slave %d already exists" % slave_id)

    def handle_request(self, query, request, mode):
        """
        Handles a request. Return value is a tuple where element 0
        is the response object and element 1 is a dictionary
        of items to log.
        """
        request_pdu = None
        response_pdu = ""
        slave_id = None
        function_code = None
        func_code = None
        slave = None
        response = None

        try:
            # extract the pdu and the slave id
            slave_id, request_pdu = query.parse_request(request)
            if len(request_pdu) > 0:
                (func_code, ) = struct.unpack(">B", request_pdu[0])
            if mode == 'tcp':
                if slave_id == 0:
                    slave = self.get_slave(slave_id)
                    response_pdu = slave.handle_request(request_pdu)
                    response = query.build_response(response_pdu)
                elif slave_id == 255:
                    # r = struct.pack(">BB", func_code + 0x80, 0x0B)
                    # response = query.build_response(r)
                    slave = self.get_slave(slave_id)
                    response_pdu = slave.handle_request(request_pdu)
                    response = query.build_response(response_pdu)
                else:
                    # return no response, and data necessary for logging
                    return (None, {'request': request_pdu.encode('hex'),
                                   'slave_id': slave_id,
                                   'function_code': func_code,
                                   'response': ''})
            elif mode == 'serial':
                if slave_id == 0:
                    for key in self._slaves:
                        response_pdu = self._slaves[key].handle_request(
                            request_pdu, broadcast=True)
                    # no response is sent
                    return (None, {'request': request_pdu.encode('hex'),
                                   'slave_id': slave_id,
                                   'function_code': func_code,
                                   'response': ''})
                elif slave_id > 0 and slave_id <= 247:
                    slave = self.get_slave(slave_id)
                    response_pdu = slave.handle_request(request_pdu)
                    # make the full response
                    response = query.build_response(response_pdu)
                else:
                    # return no response, and data necessary for logging
                    return (None, {'request': request_pdu.encode('hex'),
                                   'slave_id': slave_id,
                                   'function_code': func_code,
                                   'response': ''})
        except (IOError, MissingKeyError) as e:
            # If the request was not handled correctly, return a server error
            # response
            r = struct.pack(
                ">BB", func_code + 0x80, defines.SLAVE_DEVICE_FAILURE)
            response = query.build_response(r)
        except (ModbusInvalidRequestError) as e:
            logger.info(e)

        if slave:
            function_code = slave.function_code

        return (response, {'request': request_pdu.encode('hex'),
                           'slave_id': slave_id,
                           'function_code': function_code,
                           'response': response_pdu.encode('hex')})

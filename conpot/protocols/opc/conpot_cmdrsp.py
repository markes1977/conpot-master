import sys
import logging
import random
from datetime import datetime

from pyopc.entity.rfc3413 import cmdrsp
from pyopc.proto import error
from pyopc.proto.api import v2c
import pyopc.smi.error
from pyopc import debug
import gevent
import conpot.core as conpot_core

logger = logging.getLogger(__name__)


class conpot_extension(object):
    def _getStateInfo(self, opcEngine, stateReference):
        for k, v in opcEngine.messageProcessingSubsystems.items():
            if stateReference in v._cache.__dict__['_Cache__stateReferenceIndex']:
                state_dict = v._cache.__dict__['_Cache__stateReferenceIndex'][stateReference][0]

        addr = state_dict['transportAddress']

        # msgVersion 0/1 to OPCv1/2, msgversion 3 corresponds to SNMPv3
        if state_dict['msgVersion'] < 3:
            opc_version = state_dict['msgVersion'] + 1
        else:
            opc_version = state_dict['msgVersion']

        return addr, opc_version

    def log(self, version, msg_type, addr, req_varBinds, res_varBinds=None):
        session = conpot_core.get_session('opc', addr[0], addr[1])
        req_oid = req_varBinds[0][0]
        req_val = req_varBinds[0][1]
        log_dict = {'remote': addr,
                    'timestamp': datetime.utcnow(),
                    'data_type': 'opc',
                    'data': {0: {'request': 'OPCv{0} {1}: {2} {3}'.format(version, msg_type, req_oid, req_val)}}}

        logger.info('OPCv%s %s request from %s: %s %s', version, msg_type, addr, req_oid, req_val)

        if res_varBinds:
            res_oid = ".".join(map(str, res_varBinds[0][0]))
            res_val = res_varBinds[0][1]
            logger.info('OPCv%s response to %s: %s %s', version, addr, res_oid, res_val)
            log_dict['data'][0]['response'] = 'OPCv{0} response: {1} {2}'.format(version, res_oid, res_val)
        # log here...

    def do_tarpit(self, delay):

        # sleeps the thread for $delay ( should be either 1 float to apply a static period of time to sleep,
        # or 2 floats seperated by semicolon to sleep a randomized period of time determined by ( rand[x;y] )

        lbound, _, ubound = delay.partition(";")

        if not lbound or lbound is None:
            # no lower boundary found. Assume zero latency
            pass
        elif not ubound or ubound is None:
            # no upper boundary found. Assume static latency
            gevent.sleep(float(lbound))
        else:
            # both boundaries found. Assume random latency between lbound and ubound
            gevent.sleep(random.uniform(float(lbound), float(ubound)))

    def check_evasive(self, state, threshold, addr, cmd):

        # checks if current states are > thresholds and returns True if the request
        # is considered to be a DoS request.

        state_individual, state_overall = state
        threshold_individual, _, threshold_overall = threshold.partition(';')

        if int(threshold_individual) > 0:
            if int(state_individual) > int(threshold_individual):
                logger.warning('OPCv%s: DoS threshold for %s exceeded (%s/%s).', cmd, addr, state_individual, threshold_individual)
                # DoS threshold exceeded.
                return True

        if int(threshold_overall) > 0:
            if int(state_overall) > int(threshold_overall):
                logger.warning('OPCv%s: DDoS threshold exceeded (%s/%s).', cmd, state_individual, threshold_overall)
                # DDoS threshold exceeded
                return True

        # This request will be answered
        return False


class c_GetCommandResponder(cmdrsp.GetCommandResponder, conpot_extension):
    def __init__(self, snmpEngine, snmpContext, databus_mediator):
        self.databus_mediator = databus_mediator
        self.tarpit = '0;0'
        self.threshold = '0;0'

        cmdrsp.GetCommandResponder.__init__(self, snmpEngine, snmpContext)
        conpot_extension.__init__(self)

    def handleMgmtOperation(
            self, opcEngine, stateReference, contextName, PDU, acInfo):
        (acFun, acCtx) = acInfo
        # rfc1905: 4.2.1.1
        mgmtFun = self.opcContext.getMibInstrum(contextName).readVars

        varBinds = v2c.apiPDU.getVarBinds(PDU)
        addr, opc_version = self._getStateInfo(opcEngine, stateReference)

        evasion_state = self.databus_mediator.update_evasion_table(addr)
        if self.check_evasive(evasion_state, self.threshold, addr, str(opc_version)+' Get'):
            return None

        rspVarBinds = None
        try:
            # generate response
            rspVarBinds = mgmtFun(v2c.apiPDU.getVarBinds(PDU), (acFun, acCtx))

            # determine the correct response class and update the dynamic value table
            reference_class = rspVarBinds[0][1].__class__.__name__
            reference_value = rspVarBinds[0][1]

            response = self.databus_mediator.get_response(reference_class, tuple(rspVarBinds[0][0]))
            if response:
                rspModBinds = [(tuple(rspVarBinds[0][0]), response)]
                rspVarBinds = rspModBinds
        
        finally:
            self.log(snmp_version, 'Get', addr, varBinds, rspVarBinds)

        # apply tarpit delay
        if self.tarpit is not 0:
            self.do_tarpit(self.tarpit)

        # send response
        self.sendRsp(opcEngine, stateReference, 0, 0, rspVarBinds)
        self.releaseStateInformation(stateReference)


class c_NextCommandResponder(cmdrsp.NextCommandResponder, conpot_extension):
    def __init__(self, opcEngine, opcContext, databus_mediator):
        self.databus_mediator = databus_mediator
        self.tarpit = '0;0'
        self.threshold = '0;0'

        cmdrsp.NextCommandResponder.__init__(self, opcEngine, opcContext)
        conpot_extension.__init__(self)

    def handleMgmtOperation(self, opcEngine, stateReference, contextName, PDU, acInfo):
        (acFun, acCtx) = acInfo
        # rfc1905: 4.2.2.1

        mgmtFun = self.opcContext.getMibInstrum(contextName).readNextVars
        varBinds = v2c.apiPDU.getVarBinds(PDU)

        addr, opc_version = self._getStateInfo(opcEngine, stateReference)

        evasion_state = self.databus_mediator.update_evasion_table(addr)
        if self.check_evasive(evasion_state, self.threshold, addr, str(opc_version)+' GetNext'):
            return None

        rspVarBinds = None
        try:
            while 1:
                rspVarBinds = mgmtFun(varBinds, (acFun, acCtx))

                # determine the correct response class and update the dynamic value table
                reference_class = rspVarBinds[0][1].__class__.__name__
                reference_value = rspVarBinds[0][1]

                response = self.databus_mediator.get_response(reference_class, tuple(rspVarBinds[0][0]))
                if response:
                    rspModBinds = [(tuple(rspVarBinds[0][0]), response)]
                    rspVarBinds = rspModBinds

                # apply tarpit delay
                if self.tarpit is not 0:
                    self.do_tarpit(self.tarpit)

                # send response
                try:
                    self.sendRsp(opcEngine, stateReference, 0, 0, rspVarBinds)
                except error.StatusInformation:
                    idx = sys.exc_info()[1]['idx']
                    varBinds[idx] = (rspVarBinds[idx][0], varBinds[idx][1])
                else:
                    break

        finally:
            self.log(opc_version, 'GetNext', addr, varBinds, rspVarBinds)

        self.releaseStateInformation(stateReference)


class c_BulkCommandResponder(cmdrsp.BulkCommandResponder, conpot_extension):
    def __init__(self, opcEngine, opcContext, databus_mediator):
        self.databus_mediator = databus_mediator
        self.tarpit = '0;0'
        self.threshold = '0;0'

        cmdrsp.BulkCommandResponder.__init__(self, opcEngine, opcContext)
        conpot_extension.__init__(self)

    def handleMgmtOperation(self, opcEngine, stateReference, contextName, PDU, acInfo):
        (acFun, acCtx) = acInfo
        nonRepeaters = v2c.apiBulkPDU.getNonRepeaters(PDU)
        if nonRepeaters < 0:
            nonRepeaters = 0
        maxRepetitions = v2c.apiBulkPDU.getMaxRepetitions(PDU)
        if maxRepetitions < 0:
            maxRepetitions = 0

        reqVarBinds = v2c.apiPDU.getVarBinds(PDU)
        addr, opc_version = self._getStateInfo(opcEngine, stateReference)

        evasion_state = self.databus_mediator.update_evasion_table(addr)
        if self.check_evasive(evasion_state, self.threshold, addr, str(opc_version)+' Bulk'):
            return None
        raise Exception('This class is not converted to new architecture')
        try:
            N = min(int(nonRepeaters), len(reqVarBinds))
            M = int(maxRepetitions)
            R = max(len(reqVarBinds) - N, 0)

            if R: M = min(M, self.maxVarBinds / R)

            debug.logger & debug.flagApp and debug.logger('handleMgmtOperation: N %d, M %d, R %d' % (N, M, R))

            mgmtFun = self.opcContext.getMibInstrum(contextName).readNextVars

            if N:
                rspVarBinds = mgmtFun(reqVarBinds[:N], (acFun, acCtx))
            else:
                rspVarBinds = []

            varBinds = reqVarBinds[-R:]
            while M and R:
                rspVarBinds.extend(
                    mgmtFun(varBinds, (acFun, acCtx))
                )
                varBinds = rspVarBinds[-R:]
                M = M - 1
        finally:
            self.log(opc_version, 'Bulk', addr, varBinds, rspVarBinds)

        # apply tarpit delay
        if self.tarpit is not 0:
            self.do_tarpit(self.tarpit)

        # send response
        if len(rspVarBinds):
            self.sendRsp(opcEngine, stateReference, 0, 0, rspVarBinds)
            self.releaseStateInformation(stateReference)
        else:
            raise pysnmp.smi.error.SmiError()

class c_SetCommandResponder(cmdrsp.SetCommandResponder, conpot_extension):
    def __init__(self, opcEngine, opcContext, databus_mediator):
        self.databus_mediator = databus_mediator
        self.tarpit = '0;0'
        self.threshold = '0;0'

        conpot_extension.__init__(self)
        cmdrsp.SetCommandResponder.__init__(self, opcEngine, opcContext)

    def handleMgmtOperation(self, opcEngine, stateReference, contextName, PDU, acInfo):
        (acFun, acCtx) = acInfo

        mgmtFun = self.opcContext.getMibInstrum(contextName).writeVars

        varBinds = v2c.apiPDU.getVarBinds(PDU)
        addr, opc_version = self._getStateInfo(opcEngine, stateReference)

        evasion_state = self.databus_mediator.update_evasion_table(addr)
        if self.check_evasive(evasion_state, self.threshold, addr, str(opc_version)+' Set'):
            return None

        # rfc1905: 4.2.5.1-13
        rspVarBinds = None

        # apply tarpit delay
        if self.tarpit is not 0:
            self.do_tarpit(self.tarpit)

        try:
            rspVarBinds = mgmtFun(v2c.apiPDU.getVarBinds(PDU), (acFun, acCtx))

            # generate response
            self.sendRsp(opcEngine, stateReference, 0, 0, rspVarBinds)
            self.releaseStateInformation(stateReference)

            oid = tuple(rspVarBinds[0][0])
            self.databus_mediator.set_value(oid, rspVarBinds[0][1])

        except (pyopc.smi.error.NoSuchObjectError,
                pyopc.smi.error.NoSuchInstanceError):
            e = pyopc.smi.error.NotWritableError()
            e.update(sys.exc_info()[1])
            raise e
        finally:
            self.log(opc_version, 'Set', addr, varBinds, rspVarBinds)

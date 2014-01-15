#!/usr/bin/python

######################################################
# WebSocket test server
#
# By Andrea Faulds http://ajf.me/websocket/
#
# Licence unclear. I assume it is some OSS licence, 
# hence i fork here. But you might want to check with 
# Andrea before you fork from me :-) /nils.
######################################################


from twisted.internet import protocol, reactor
from txws import WebSocketFactory

class Echo(protocol.Protocol):
    def dataReceived(self, data):
        self.transport.write(data)

class EchoFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return Echo()

reactor.listenTCP(8080, WebSocketFactory(EchoFactory()))
reactor.run()


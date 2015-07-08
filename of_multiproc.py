'''
Based on of_tutorial.py from the Mininet OpenFlow tutorial
with additional socket running concurrently
'''
# Copyright 2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""


from pox.core import core
import pox.openflow.libopenflow_01 as of
from multiprocessing import Process, Pipe, Queue
import os
import socket
import sys
from thread import *
#import thread


log = core.getLogger()


class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def switch (self, packet, packet_in):
    """
    Implement switch-like behavior.
    """

    # Here's some psuedocode to start you off implementing a learning
    # switch.  You'll need to rewrite it as real Python code.

    # Learn the port for the source MAC
    #self.mac_to_port ... <add or update entry>
    if packet.src not in self.mac_to_port:
      #log.debug("Learning %s source port" % packet.src)
      self.mac_to_port[packet.src]=packet_in.in_port

    # if the port associated with the destination MAC of the packet is known:
    if packet.dst in self.mac_to_port:
      #log.debug("Destination of packet known")
      # Send packet out the associated port
      #self.resend_packet(packet_in, ...)

      #self.resend_packet(packet_in,self.mac_to_port[packet.dst])

      # Once you have the above working, try pushing a flow entry
      # instead of resending the packet (comment out the above and
      # uncomment and complete the below.)

      #log.debug("Installing flow")
      #log.debug("source: %s" % packet.src)
      #log.debug("destination: %s" % packet.dst)
      # Maybe the log statement should have source/destination/port?

      msg = of.ofp_flow_mod()

      # Set fields to match received packet
      msg.match = of.ofp_match.from_packet(packet_in)
      msg.priority = 100
      msg.buffer_id = packet_in.buffer_id

      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      #msg.idle_timeout = 5
      #msg.hard_timeout = 20

      #< Add an output action, and send -- similar to resend_packet() >
      port_out = self.mac_to_port[packet.dst]
      out_action = of.ofp_action_output(port = port_out)
      msg.actions.append(out_action)
      #log.debug("action appended")
      #print "msg: %s" % msg
      self.connection.send(msg)
      #log.debug("msg sent")

    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      #log.debug("Destination of packet unknown")
      self.resend_packet(packet_in, of.OFPP_ALL)
      #log.debug("Flooding packet...") 


  def limited_ip_switch ( self, packet, packet_in, host_ip, serv_ip ):
    '''
    Only forwards packets sent between a given host and server.
    Action is empty for all other packets reaching the switch,
    forcing them to drop.
    '''
    def add_action ():
      port_out = self.mac_to_port[ packet.dst ]
      out_action = of.ofp_action_output( port = port_out )
      msg.actions.append( out_action )

    if packet.src not in self.mac_to_port:
      self.mac_to_port[ packet.src ] = packet_in.in_port

    if packet.dst in self.mac_to_port:
      msg = of.ofp_flow_mod()

      msg.match = of.ofp_match.from_packet( packet_in )
      msg.priority = 65535
      msg.buffer_id = packet_in.buffer_id

      #msg.idle_timeout = 5
      #msg.hard_timeout = 20

      if msg.match.nw_src == host_ip and msg.match.nw_dst == serv_ip:
        add_action()
      elif msg.match.nw_src == serv_ip and msg.match.nw_dst == host_ip:
        add_action()

      self.connection.send( msg )

    else:
      self.resend_packet( packet_in, of.OFPP_ALL )


  def limited_ip_switch2 ( self, packet, packet_in, ip_list ):
    '''
    Only forwards packets between hosts with IP addresses in a given list.
    '''
    def add_action ():
      port_out = self.mac_to_port[ packet.dst ]
      out_action = of.ofp_action_output( port = port_out )
      msg.actions.append( out_action )

    if packet.src not in self.mac_to_port:
      self.mac_to_port[ packet.src ] = packet_in.in_port

    if packet.dst in self.mac_to_port:
      msg = of.ofp_flow_mod()

      msg.match = of.ofp_match.from_packet( packet_in )
      msg.priority = 65535
      msg.buffer_id = packet_in.buffer_id

      #msg.idle_timeout = 5
      #msg.hard_timeout = 20

      if msg.match.nw_src in ip_list and msg.match.nw_dst in ip_list:
        add_action()

      self.connection.send( msg )

    else:
      self.resend_packet( packet_in, of.OFPP_ALL )


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    #self.switch( packet, packet_in )
    #self.limited_ip_switch( packet, packet_in, '10.0.0.2', '10.0.0.1' )
    ip_list = ( '10.0.0.1', '10.0.0.2', '10.0.0.3' )
    self.limited_ip_switch2( packet, packet_in, ip_list )


def launch ():
  """
  Starts the component
  """
  info('function launch')
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)

  '''
  #pox_conn, sox_conn = Pipe()
  q = Queue()
  sox = Process(target=socket_server, args=(q,))
  sox.daemon = True
  sox.start()
  print "sox process created"
  #print pox_conn.recv()
  while True:
    print q.get()
  '''

  sox = Process(target=socket_server)
  sox.start()


#'''
def info(title):
  print '**********'
  print title
  print 'module name:', __name__
  if hasattr(os, 'getppid'):
    print 'parent process:', os.getppid()
  print 'process id:', os.getpid()
  print '**********'
#'''

def socket_server ():
  info('function socket_server')
  host = ''
  port = 8888

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  #print "Socket created"

  try:
    s.bind((host,port))
  except socket.error, msg:
    print "Bind failed. Error code: %s, Message: %s" %(str(msg[0]), msg[1])
    sys.exit()
  #print "Socket bind complete"

  s.listen(5)
  #print "Socket now listening"

  def clientthread(conn):
    conn.send("Type something and hit enter:\n")

    while True:
      data = conn.recv(1024)
      #print "Data:", data

      if "exit" in data:
        print "EXITING"
        #q.put("Exiting")
        #q.send("Exiting")
        #q.close()
        break

      reply = "OK... %s" % data

      if not data:
        break

      conn.sendall(reply)

    conn.close()

  while True:
    conn, addr = s.accept()
    #print "Connected with %s: %s" %(addr[0], str(addr[1]))

    start_new_thread(clientthread, (conn,))

  s.close()


'''
info('main body')

#pox_conn, pox2_conn = Pipe()
#sox_conn, sox2_conn = Pipe()

#pox = Process(target=launch, args=(pox_conn,))
pox = Process(target=launch)
pox.start()
#pox.join()
print "Process 'pox' created"

#sox = Process(target=socket_server, args=(sox_conn,))
sox = Process(target=socket_server)
sox.start()
#sock.join()
print "Process 'sox' created"
'''

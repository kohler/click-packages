#ifndef CLICK_SNMPTRAPSOURCE_HH
#define CLICK_SNMPTRAPSOURCE_HH
#include <click/element.hh>
#include <click/atomic.hh>
#include <click/task.hh>
#include <click/standard/storage.hh>
#include "snmpbasics.hh"

/*
=c

SNMPTrapSource(I<KEYWORDS>)

=s SNMP

generates SNMP traps on demand

=d

SNMPTrapSource generates SNMP traps on demand. When the user writes to one of
its trap-generation handlers, SNMPTrapSource constructs the corresponding
trap, optionally including the values of some SNMP variables, and emits it on
its first output.

Keyword arguments are:

=over 8

=item UDP

Boolean. If true, then SNMPTrapSource generates UDP-in-IP packets. If false,
then SNMPTrapSource generates packets without UDP or IP encapsulation. Default
is true.

=item TTL

Byte. Specifies the generated IP header's time-to-live field (if the C<IP>
keyword argument is true). Default is 255.

=item SRC

IP address. Specifies the address of the SNMP agent generating the traps. Used
for the IP header's source field, and for a field in the trap proper.

=item SPORT

Unsigned short. Specifies the UDP source port for generated traps.

=item DST

IP address. Specifies the address where traps should be sent. Used
in the IP header, if IP is true.

=item DPORT

Unsigned short. Specifies the UDP destination port for generated traps.
Default is 162 (snmp-trap).

=item COMMUNITY

String. The SNMP community string. Default is C<"public">.

=item ENTERPRISE

SNMP OID. The SNMP enterprise generating the trap.

=item TRAP

Trap specification, as defined below. There may be multiple TRAP arguments.

=item ACTIVE

Boolean. Specifies whether packets will actually be sent when any of the
send_TRAPNAME handlers are poked. Default is true.

=back

The user must supply at least the ENTERPRISE and SPORT keyword arguments. If
IP is true, then SRC and DST must be supplied as well. An SNMPTrapSource
element is useless without at least one TRAP argument.

=head1 TRAP SPECIFICATIONS

Trap specifications look like "NAME [SPECIFIC] [VARIABLES...]". NAME is a
textual name used to identify the trap. It may be one of SNMP's well-known
trap types, "C<coldStart>", "C<warmStart>", "C<linkDown>", "C<linkUp>",
"C<authenticationFailure>", or "C<egpNeighborLoss>", or an arbitrary nonempty
string, which represents an C<enterpriseSpecific> trap. These
enterpriseSpecific traps may optionally specify a specific code with the
SPECIFIC argument. This is a nonnegative integer that defaults to 0.

The VARIABLES argument is a space-separated list of SNMP object IDs
corresponding to SNMP variables; see SNMPVariableInfo. When trap NAME is
generated, the values of the VARIABLES are encoded into the trap packet.

=h send_TRAPNAME write-only

A C<send_TRAPNAME> handler exists for each TRAP argument; TRAPNAME corresponds
to the trap's name. Writing an arbitrary string to this handler causes
SNMPTrapSource to generate the corresponding trap and emit it on output 0.

=h enterprise read-only

Returns the ENTERPRISE argument, an SNMP OID.

=h traps read-only

Returns the trap names this SNMPTrapSource understands, one per line.

=h src read/write

Returns or sets the SRC argument.

=h dst read/write

Returns or sets the DST argument.

=h sport read/write

Returns or sets the SPORT argument.

=h dport read/write

Returns or sets the DPORT argument.

=h active read/write

Returns or sets the ACTIVE argument.

=h drops read-only

Returns the number of traps dropped due to queue overflow or out-of-memory
conditions.

=a

SNMPVariableInfo, SNMPOidInfo */

class SNMPTrapSource : public Element, public Storage { public:

  SNMPTrapSource();
  ~SNMPTrapSource();
  
  const char *class_name() const	{ return "SNMPTrapSource"; }
  const char *port_count() const	{ return PORTS_0_1; }
  void *cast(const char *);
  const char *processing() const	{ return PUSH; }

  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  void cleanup(CleanupStage);
  void add_handlers();

  int generate_trap(int);
  bool run_task(Task *);
  
 private:

  static const int QSIZE = 15;
  Packet *_queue[QSIZE+1];
  uatomic32_t _drops;
  
  IPAddress _src;
  IPAddress _dst;
  IPAddress _agent;
  unsigned short _sport;
  unsigned short _dport;
  String _community;
  SNMPOid _enterprise;
  uatomic32_t _jiffies0;
  
  bool _udp_encap;
  unsigned char _ip_ttl;
  uatomic32_t _id;

  Vector<String> _names;
  Vector<int> _trap_types;
  Vector<int> _offsets;
  Vector<int> _snmp_vars;

  Task _task;
  bool _active;

  int add_trap(const String &, ErrorHandler *);

  enum { H_drops, H_enterprise, H_src, H_dst, H_sport, H_dport, H_traps, H_active };
  static String read_handler(Element *, void *);
  static int write_handler(const String &, Element *, void *, ErrorHandler *);
  
};

#endif

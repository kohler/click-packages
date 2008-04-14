#ifndef CLICK_SNMPVARINFO_HH
#define CLICK_SNMPVARINFO_HH
#include "snmpbasics.hh"
#include "snmpoidtree.hh"
#include <click/element.hh>
#include <click/hashtable.hh>
class SNMPBEREncoder;

/*
=c

SNMPVariableInfo(OID TYPE [HANDLER], ...)

=s SNMP

assigns variable semantics to SNMP OIDs

=io

None

=d

SNMPVariableInfo sets up a correspondence between SNMP OIDs and Click
handlers. When an element like SNMPTrapSource wants to generate an SNMP
variable binding, it will call the handler specified by SNMPVariableInfo.

Each argument specifies an SNMP OID and the SNMP type of the corresponding
variable. Valid types are:

=over 8

=item C<INTEGER> or C<Integer32>

A 32-bit integer.

=item C<"OCTET STRING">

A string of bytes.

=item C<DisplayString>

A string of at most 255 ASCII characters.

=item C<NULL>

No data.

=item C<IPAddress>

An IPv4 address.

=item C<Gauge> or C<Gauge32> or C<Unsigned32>

A 32-bit unsigned integer.

=item C<Counter> or C<Counter32>

A 32-bit unsigned integer with wraparound comparison.

=item C<TimeTicks>

A 32-bit unsigned integer representing time.

=back

All TYPEs except for C<NULL> must be followed by HANDLER, a handler ID. When
another element wants to discover that variable's value, SNMPVariableInfo will
call the specified handler and parse its value. For example, consider this
configuration fragment:

  ... -> c :: Counter -> ...
  SNMPVariableInfo(1.3.6.1.2.1.6.44 Counter32 c.count);

The SNMP OID "1.3.6.1.2.1.6.44" has type Counter32, and its value corresponds
to the C<c.count> handler. When another element requests the value of
"1.3.6.1.2.1.6.44.0", SNMPVariableInfo will call C<c.count>, parse its value,
and return the corresponding unsigned integer.

Note, in this example, that the other element requested
"1.3.6.1.2.1.6.44B<.0>". The final ".0" indicates that "1.3.6.1.2.1.6.44" is a
scalar variable: Counter32 is a scalar type. This ".0" is required; searching
for "1.3.6.1.2.1.6.44" will not work.

SNMP variable definitions are global. They are not scoped by compound
elements, for example.

=a

SNMPOidInfo, SNMPTrapSource */

typedef int SNMPVariable;
  
class SNMPVariableInfo : public Element { public:

  SNMPVariableInfo();
  ~SNMPVariableInfo();
  
  const char *class_name() const	{ return "SNMPVariableInfo"; }

  int configure_phase() const	{ return CONFIGURE_PHASE_SNMP_VARINFO; }
  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  int add_info(const String &, const String &prefix, ErrorHandler *);

  static SNMPVariable query(const SNMPOid &, Element *);
  static bool int_value(SNMPVariable, Element *, int *);
  static bool unsigned_value(SNMPVariable, Element *, unsigned *);
  static bool encode_binding(SNMPVariable, SNMPBEREncoder &, Element *);
  static SNMPVariableInfo *find_element(Element *);
  
 private:

  SNMPOidTree _tree;
  Vector<int> _tags;
  Vector<Element *> _handler_elements;
  Vector<const Handler *> _handlers;
  Vector<SNMPOidTree::Node *> _nodes;

  void extract_tree_oid(int tree_ptr, SNMPVariable *) const;
  int find_tree_ptr(const SNMPVariable &oid);
  int do_configure(Vector<String> &, bool, ErrorHandler *);
  int add_info(const String &, const String &prefix, ErrorHandler *, bool);
  int set_variable_handler(int, const String &, ErrorHandler *);
  
};

inline int
SNMPVariableInfo::add_info(const String &str, const String &prefix, ErrorHandler *errh)
{
  return add_info(str, prefix, errh, true);
}

#endif

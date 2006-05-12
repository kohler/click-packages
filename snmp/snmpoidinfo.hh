#ifndef CLICK_SNMPOIDINFO_HH
#define CLICK_SNMPOIDINFO_HH
#include "snmpbasics.hh"
#include "snmpoidtree.hh"
#include <click/element.hh>
#include <click/hashmap.hh>

/*
=c

SNMPOidInfo(NAME OID, ...)

=s SNMP

assigns names to SNMP object identifiers

=io

None

=d

SNMPOidInfo introduces shorthand names for SNMP object identifiers.

An SNMP object identifier, or "OID", represents a variable interesting to some
SNMP manager or agent. It is a sequence of nonnegative 32-bit integers
separated by periods. For example:

   1.3.6.1.4.1

SNMPOidInfo introduces names that represent object identifiers or their
prefixes. For example, the name "C<internet>" means "C<1.3.6.1>", and these
two lines represent the same OID:

   1.3.6.1.4.1
   internet.4.1

SNMPOidInfo's configuration arguments each consist of two space-separated
words: an SNMP identifier and the corresponding OID. The "C<internet>" name is
defined by default, but if it were not, it could be introduced with
SNMPOidInfo like this:

   SNMPOidInfo(internet 1.3.6.1);

SNMP OID definitions are scoped by compound elements. If an SNMPOidInfo
element is included within a compound element, then its definitions only
become available inside that compound element.

It is an error to define a name with two different values in the same scope.

=head1 OBJECT IDENTIFIERS

Click allows you to write SNMP object identifiers with dotted numbers only, or
with a mix of numbers and identifiers. Each identifier represents a prefix of
the OID being specified. For example, "C<internet.4.1>" means
"C<1.3.6.1.4.1>": the "C<internet>" identifier corresponds to the prefix
"C<1.3.6.1>". Identifiers can also be used in the middle of an OID
representation. The OID text is parsed componentwise from left to right,
building an accumulated OID. Each identifier component must correspond to an
OID at least as long as the OID that had been parsed so far. Furthermore, if
that accumulated OID is not empty, then the identifier's OID must agree with
the accumulated OID where they overlap. If these conditions are met, then the
accumulated OID is replaced by the identifier's OID, and parsing continues.
For example, say the following definitions are in effect:

   iso        corresponds to   1
   internet   corresponds to   1.3.6.1 

Then these OID representations are valid:

   1.3.6.1.4           corresponds to    1.3.6.1.4
   iso.3.6.1.4         corresponds to    1.3.6.1.4
   internet.4          corresponds to    1.3.6.1.4
   iso.internet.4      corresponds to    1.3.6.1.4
   1.3.6.internet.4    corresponds to    1.3.6.1.4

These representations, however, will cause parse errors:

   2.internet.4        OID 'internet' (1.3.6.1) conflicts with context (2)
   internet.iso.4      OID 'iso' (1) too short for context (1.3.6.1)

=head1 WELL-KNOWN OID DEFINITIONS

The following OID definitions are always available. You need not define them
with SNMPOidInfo, and you may not redefine them in any scope.

  ccitt			0
  iso			1
  org			1.3
  dod			1.3.6
  internet		1.3.6.1
  joint-iso-ccitt	2
  
  mgmt			internet.2	1.3.6.1.2
  experimental		internet.3	1.3.6.1.3
  private		internet.4	1.3.6.1.4
  enterprises		internet.4.1	1.3.6.1.4.1
  snmpv2		internet.6	1.3.6.1.6
  
  mib			mgmt.1		1.3.6.1.2.1
  mib-2			mgmt.1		1.3.6.1.2.1
  system		mib-2.1		1.3.6.1.2.1.1
  interfaces		mib-2.2		1.3.6.1.2.1.2
  at			mib-2.3		1.3.6.1.2.1.3
  ip			mib-2.4		1.3.6.1.2.1.4
  icmp			mib-2.5		1.3.6.1.2.1.5
  tcp			mib-2.6		1.3.6.1.2.1.6
  udp			mib-2.7		1.3.6.1.2.1.7
  egp			mib-2.8		1.3.6.1.2.1.8
  transmission		mib-2.10	1.3.6.1.2.1.10
  snmp			mib-2.11	1.3.6.1.2.1.11

=a

SNMPVariableInfo */

class SNMPOidInfo : public Element { public:
  
  SNMPOidInfo();
  ~SNMPOidInfo();

  static void static_initialize();
  static void static_cleanup();

  const char *class_name() const	{ return "SNMPOidInfo"; }

  int configure_phase() const	{ return CONFIGURE_PHASE_SNMP_OIDINFO; }
  int configure(Vector<String> &, ErrorHandler *);
  int add_info(const String &arg, const String &prefix, ErrorHandler *);

  static SNMPOidInfo *find_element(Element *);
  bool query(const String &identifier, String context, SNMPOid *) const;

  static SNMPOidInfo *well_known_oids;
  
 private:

  HashMap<String, int> _map;
  Vector<String> _context;
  Vector<int> _next;
  Vector<SNMPOidTree::Node *> _tree_ptr;

  SNMPOidTree _tree;

  void extract_tree_oid(int, SNMPOid *) const;
  int find_tree_ptr(const SNMPOid &oid);
  
};


inline void
SNMPOidInfo::extract_tree_oid(int i, SNMPOid *oid) const
{
  _tree.extract_oid(_tree_ptr[i], oid);
}

#endif

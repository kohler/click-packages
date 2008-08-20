#!/usr/bin/python
#
# Generates ipfixtypes.hh from IPFIX spec and schema
#
# Copyright (c) 2006 Mazu Networks, Inc.
#
# $Id: ipfixtypes.py,v 1.1 2006/05/12 16:43:44 eddietwo Exp $
#

import xml.dom.minidom
import sys
import time

class IPFIXField:
    """
    Represents a <field> element in the IPFIX specification. Access
    attributes with getattr(), e.g.,

    field.name or getattr(field, 'name')
    field.dataType or getattr(field, 'dataType')
    """

    def __init__(self, node):
        self.node = node

    def __getattr__(self, name):
        return self.node.getAttribute(name)

class IPFIXSpecification:
    """
    Represents all <field> elements in the IPFIX specification.
    """

    def __init__(self, file = None):
        dom = xml.dom.minidom.parse(file)

        self.fields = []
        for fieldDefinitions in dom.getElementsByTagName('fieldDefinitions'):
            self.fields += [IPFIXField(field) for field in fieldDefinitions.getElementsByTagName('field')]

        self.types = []
        for simpleType in dom.getElementsByTagName('simpleType'):
            if simpleType.getAttribute('name') == "dataType":
                for enumeration in simpleType.getElementsByTagName('enumeration'):
                    self.types.append(enumeration.getAttribute('value'))

    def fieldDefinitions(self):
        """
        Returns all fields declared in the <fieldDefinitions>
        section of the specification.
        """

        return self.fields

    def dataTypes(self):
        """
        Returns all dataTypes declared in the <schema> section of the
        specification.
        """

        return self.types

def main():
    if len(sys.argv) < 2:
        print "Usage: %s [OPTION]... [FILE]..." % sys.argv[0]
        sys.exit(0)

    dataTypes = {}
    fieldTypes = {}

    for file in sys.argv[1:]:
        spec = IPFIXSpecification(file)
        for field in spec.fieldDefinitions():
            if dataTypes.has_key(field.dataType):
                dataTypes[field.dataType].append(field.name)
            else:
                dataTypes[field.dataType] = [field.name]
            fieldTypes[int(field.fieldId)] = field.name
        for dataType in spec.dataTypes():
            if not dataTypes.has_key(dataType):
                dataTypes[dataType] = []

    # IPFIX_unsigned8,
    data_types = ["IPFIX_%s" % dataType for dataType in dataTypes]
    data_types = ",\n  ".join(data_types)

    # IPFIX_octetDeltaCount = 1,
    field_types = fieldTypes.items()
    field_types.sort()
    field_types = ["IPFIX_%s = %d" % (name, fieldId) for fieldId, name in field_types]
    field_types = ",\n  ".join(field_types)

    # case IPFIX_octetDeltaCount:
    # case IPFIX_packetDeltaCount:
    # ...
    #   return IPFIX_unsigned64;
    ipfix_datatypes = []
    for dataType, names in dataTypes.iteritems():
        if names:
            ipfix_datatypes += ["case IPFIX_%s:" % name for name in names]
            ipfix_datatypes.append("  return IPFIX_%s;" % dataType)
    ipfix_datatypes = "\n  ".join(ipfix_datatypes)

    # case IPFIX_octetDeltaCount: return "octetDeltaCount";
    ipfix_names = ["case IPFIX_%s: return \"%s\";" % \
                   (name, name) for name in fieldTypes.values()]
    ipfix_names = "\n  ".join(ipfix_names)

    # else if (strcmp(name, "octetDeltaCount") == 0) { return IPFIX_octetDeltaCount; }
    ipfix_types = ["else if (strcmp(name, \"%s\") == 0) { return IPFIX_%s; }" % \
                   (name, name) for name in fieldTypes.values()]
    ipfix_types = "\n  ".join(ipfix_types)

    date = time.asctime()

    print """
// DO NOT EDIT. Generated at %(date)s.

#ifndef IPFIXTYPES_HH
#define IPFIXTYPES_HH

enum IPFIX_dataType {
  IPFIX_unknown = 0,
  %(data_types)s
};

enum IPFIX_fieldType {
  %(field_types)s
};

static inline IPFIX_dataType
ipfix_datatype(uint16_t type) {
  switch (type) {
  %(ipfix_datatypes)s
  }
  return IPFIX_unknown;
}

static inline const char *
ipfix_name(uint16_t type) {
  switch (type) {
  %(ipfix_names)s
  }
  return "unknown";
}

static inline uint16_t
ipfix_type(const char *name) {
  if (0) { }
  %(ipfix_types)s
  else { return 0; }
}

#endif
""".strip() % locals()

if __name__ == '__main__':
    main()

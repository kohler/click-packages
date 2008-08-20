// DO NOT EDIT. Generated at Wed Aug 20 11:25:20 2008.

#ifndef IPFIXTYPES_HH
#define IPFIXTYPES_HH

enum IPFIX_dataType {
  IPFIX_unknown = 0,
  IPFIX_ipv4Address,
  IPFIX_macAddress,
  IPFIX_string,
  IPFIX_unsigned16,
  IPFIX_dateTimeNanoSeconds,
  IPFIX_octet,
  IPFIX_octetArray,
  IPFIX_unsigned32,
  IPFIX_dateTimeMilliSeconds,
  IPFIX_dateTimeSeconds,
  IPFIX_boolean,
  IPFIX_dateTimeMicroSeconds,
  IPFIX_unsigned64,
  IPFIX_ipv6Address,
  IPFIX_float32
};

enum IPFIX_fieldType {
  IPFIX_octetDeltaCount = 1,
  IPFIX_packetDeltaCount = 2,
  IPFIX_protocolIdentifier = 4,
  IPFIX_classOfServiceIPv4 = 5,
  IPFIX_tcpControlBits = 6,
  IPFIX_sourceTransportPort = 7,
  IPFIX_sourceIPv4Address = 8,
  IPFIX_sourceIPv4Mask = 9,
  IPFIX_ingressInterface = 10,
  IPFIX_destinationTransportPort = 11,
  IPFIX_destinationIPv4Address = 12,
  IPFIX_destinationIPv4Mask = 13,
  IPFIX_egressInterface = 14,
  IPFIX_ipNextHopIPv4Address = 15,
  IPFIX_bgpSourceAsNumber = 16,
  IPFIX_bgpDestinationAsNumber = 17,
  IPFIX_bgpNextHopIPv4Address = 18,
  IPFIX_postMCastPacketDeltaCount = 19,
  IPFIX_postMCastOctetDeltaCount = 20,
  IPFIX_flowEndSysUpTime = 21,
  IPFIX_flowStartSysUpTime = 22,
  IPFIX_postOctetDeltaCount = 23,
  IPFIX_postPacketDeltaCount = 24,
  IPFIX_minimumPacketLength = 25,
  IPFIX_maximumPacketLength = 26,
  IPFIX_sourceIPv6Address = 27,
  IPFIX_destinationIPv6Address = 28,
  IPFIX_sourceIPv6Mask = 29,
  IPFIX_destinationIPv6Mask = 30,
  IPFIX_flowLabelIPv6 = 31,
  IPFIX_icmpTypeCodeIPv4 = 32,
  IPFIX_igmpType = 33,
  IPFIX_flowActiveTimeOut = 36,
  IPFIX_flowInactiveTimeout = 37,
  IPFIX_exportedOctetTotalCount = 40,
  IPFIX_exportedMessageTotalCount = 41,
  IPFIX_exportedFlowTotalCount = 42,
  IPFIX_sourceIPv4Prefix = 44,
  IPFIX_destinationIPv4Prefix = 45,
  IPFIX_mplsTopLabelType = 46,
  IPFIX_mplsTopLabelIPv4Address = 47,
  IPFIX_minimumTtl = 52,
  IPFIX_maximumTtl = 53,
  IPFIX_identificationIPv4 = 54,
  IPFIX_postClassOfServiceIPv4 = 55,
  IPFIX_sourceMacAddress = 56,
  IPFIX_postDestinationMacAddr = 57,
  IPFIX_vlanId = 58,
  IPFIX_postVlanId = 59,
  IPFIX_ipVersion = 60,
  IPFIX_ipNextHopIPv6Address = 62,
  IPFIX_bgpNextHopIPv6Address = 63,
  IPFIX_ipv6ExtensionHeaders = 64,
  IPFIX_mplsTopLabelStackEntry = 70,
  IPFIX_mplsLabelStackEntry2 = 71,
  IPFIX_mplsLabelStackEntry3 = 72,
  IPFIX_mplsLabelStackEntry4 = 73,
  IPFIX_mplsLabelStackEntry5 = 74,
  IPFIX_mplsLabelStackEntry6 = 75,
  IPFIX_mplsLabelStackEntry7 = 76,
  IPFIX_mplsLabelStackEntry8 = 77,
  IPFIX_mplsLabelStackEntry9 = 78,
  IPFIX_mplsLabelStackEntry10 = 79,
  IPFIX_destinationMacAddress = 80,
  IPFIX_postSourceMacAddress = 81,
  IPFIX_interfaceName = 82,
  IPFIX_interfaceDescription = 83,
  IPFIX_samplerName = 84,
  IPFIX_octetTotalCount = 85,
  IPFIX_packetTotalCount = 86,
  IPFIX_fragmentOffsetIPv4 = 88,
  IPFIX_bgpNextAdjacentAsNumber = 128,
  IPFIX_bgpPrevAdjacentAsNumber = 129,
  IPFIX_exporterIPv4Address = 130,
  IPFIX_exporterIPv6Address = 131,
  IPFIX_droppedOctetDeltaCount = 132,
  IPFIX_droppedPacketDeltaCount = 133,
  IPFIX_droppedOctetTotalCount = 134,
  IPFIX_droppedPacketTotalCount = 135,
  IPFIX_flowEndReason = 136,
  IPFIX_classOfServiceIPv6 = 137,
  IPFIX_postClassOfServiceIPv6 = 138,
  IPFIX_icmpTypeCodeIPv6 = 139,
  IPFIX_mplsTopLabelIPv6Address = 140,
  IPFIX_lineCardId = 141,
  IPFIX_portId = 142,
  IPFIX_meteringProcessId = 143,
  IPFIX_exportingProcessId = 144,
  IPFIX_templateId = 145,
  IPFIX_wlanChannelId = 146,
  IPFIX_wlanSsid = 147,
  IPFIX_flowId = 148,
  IPFIX_sourceId = 149,
  IPFIX_flowStartSeconds = 150,
  IPFIX_flowEndSeconds = 151,
  IPFIX_flowStartMilliSeconds = 152,
  IPFIX_flowEndMilliSeconds = 153,
  IPFIX_flowStartMicroSeconds = 154,
  IPFIX_flowEndMicroSeconds = 155,
  IPFIX_flowStartNanoSeconds = 156,
  IPFIX_flowEndNanoSeconds = 157,
  IPFIX_flowStartDeltaMicroSeconds = 158,
  IPFIX_flowEndDeltaMicroSeconds = 159,
  IPFIX_systemInitTimeMilliSeconds = 160,
  IPFIX_flowDurationMilliSeconds = 161,
  IPFIX_flowDurationMicroSeconds = 162,
  IPFIX_observedFlowTotalCount = 163,
  IPFIX_ignoredPacketTotalCount = 164,
  IPFIX_ignoredOctetTotalCount = 165,
  IPFIX_notSentFlowTotalCount = 166,
  IPFIX_notSentPacketTotalCount = 167,
  IPFIX_notSentOctetTotalCount = 168,
  IPFIX_destinationIPv6Prefix = 169,
  IPFIX_sourceIPv6Prefix = 170,
  IPFIX_postOctetTotalCount = 171,
  IPFIX_postPacketTotalCount = 172,
  IPFIX_flowKeyIndicator = 173,
  IPFIX_postMCastPacketTotalCount = 174,
  IPFIX_postMCastOctetTotalCount = 175,
  IPFIX_icmpTypeIPv4 = 176,
  IPFIX_icmpCodeIPv4 = 177,
  IPFIX_icmpTypeIPv6 = 178,
  IPFIX_icmpCodeIPv6 = 179,
  IPFIX_udpSourcePort = 180,
  IPFIX_udpDestinationPort = 181,
  IPFIX_tcpSourcePort = 182,
  IPFIX_tcpDestinationPort = 183,
  IPFIX_tcpSequenceNumber = 184,
  IPFIX_tcpAcknowledgementNumber = 185,
  IPFIX_tcpWindowSize = 186,
  IPFIX_tcpUrgentPointer = 187,
  IPFIX_tcpHeaderLength = 188,
  IPFIX_ipHeaderLength = 189,
  IPFIX_totalLengthIPv4 = 190,
  IPFIX_payloadLengthIPv6 = 191,
  IPFIX_ipTimeToLive = 192,
  IPFIX_nextHeaderIPv6 = 193,
  IPFIX_ipClassOfService = 194,
  IPFIX_ipDiffServCodePoint = 195,
  IPFIX_ipPrecedence = 196,
  IPFIX_fragmentFlagsIPv4 = 197,
  IPFIX_octetDeltaSumOfSquares = 198,
  IPFIX_octetTotalSumOfSquares = 199,
  IPFIX_mplsTopLabelTtl = 200,
  IPFIX_mplsLabelStackLength = 201,
  IPFIX_mplsLabelStackDepth = 202,
  IPFIX_mplsTopLabelExp = 203,
  IPFIX_ipPayloadLength = 204,
  IPFIX_udpMessageLength = 205,
  IPFIX_isMulticast = 206,
  IPFIX_internetHeaderLengthIPv4 = 207,
  IPFIX_ipv4Options = 208,
  IPFIX_tcpOptions = 209,
  IPFIX_paddingOctets = 210,
  IPFIX_headerLengthIPv4 = 213,
  IPFIX_mplsPayloadLength = 214
};

static inline IPFIX_dataType
ipfix_datatype(uint16_t type) {
  switch (type) {
  case IPFIX_sourceIPv4Address:
  case IPFIX_sourceIPv4Prefix:
  case IPFIX_destinationIPv4Address:
  case IPFIX_destinationIPv4Prefix:
  case IPFIX_ipNextHopIPv4Address:
  case IPFIX_bgpNextHopIPv4Address:
  case IPFIX_mplsTopLabelIPv4Address:
  case IPFIX_exporterIPv4Address:
    return IPFIX_ipv4Address;
  case IPFIX_sourceMacAddress:
  case IPFIX_postSourceMacAddress:
  case IPFIX_destinationMacAddress:
  case IPFIX_postDestinationMacAddr:
    return IPFIX_macAddress;
  case IPFIX_interfaceName:
  case IPFIX_interfaceDescription:
  case IPFIX_samplerName:
  case IPFIX_wlanSsid:
    return IPFIX_string;
  case IPFIX_identificationIPv4:
  case IPFIX_fragmentOffsetIPv4:
  case IPFIX_totalLengthIPv4:
  case IPFIX_sourceTransportPort:
  case IPFIX_destinationTransportPort:
  case IPFIX_udpSourcePort:
  case IPFIX_udpDestinationPort:
  case IPFIX_udpMessageLength:
  case IPFIX_tcpSourcePort:
  case IPFIX_tcpDestinationPort:
  case IPFIX_tcpWindowSize:
  case IPFIX_tcpUrgentPointer:
  case IPFIX_tcpHeaderLength:
  case IPFIX_icmpTypeCodeIPv4:
  case IPFIX_icmpTypeCodeIPv6:
  case IPFIX_vlanId:
  case IPFIX_postVlanId:
  case IPFIX_bgpSourceAsNumber:
  case IPFIX_bgpDestinationAsNumber:
  case IPFIX_bgpNextAdjacentAsNumber:
  case IPFIX_bgpPrevAdjacentAsNumber:
  case IPFIX_minimumPacketLength:
  case IPFIX_maximumPacketLength:
  case IPFIX_flowActiveTimeOut:
  case IPFIX_flowInactiveTimeout:
  case IPFIX_templateId:
    return IPFIX_unsigned16;
  case IPFIX_flowStartNanoSeconds:
  case IPFIX_flowEndNanoSeconds:
    return IPFIX_dateTimeNanoSeconds;
  case IPFIX_ipVersion:
  case IPFIX_sourceIPv4Mask:
  case IPFIX_sourceIPv6Mask:
  case IPFIX_destinationIPv4Mask:
  case IPFIX_destinationIPv6Mask:
  case IPFIX_ipTimeToLive:
  case IPFIX_protocolIdentifier:
  case IPFIX_nextHeaderIPv6:
  case IPFIX_ipClassOfService:
  case IPFIX_ipDiffServCodePoint:
  case IPFIX_ipPrecedence:
  case IPFIX_classOfServiceIPv4:
  case IPFIX_postClassOfServiceIPv4:
  case IPFIX_classOfServiceIPv6:
  case IPFIX_postClassOfServiceIPv6:
  case IPFIX_isMulticast:
  case IPFIX_fragmentFlagsIPv4:
  case IPFIX_ipHeaderLength:
  case IPFIX_headerLengthIPv4:
  case IPFIX_internetHeaderLengthIPv4:
  case IPFIX_icmpTypeIPv4:
  case IPFIX_icmpCodeIPv4:
  case IPFIX_icmpTypeIPv6:
  case IPFIX_icmpCodeIPv6:
  case IPFIX_igmpType:
  case IPFIX_wlanChannelId:
  case IPFIX_mplsTopLabelExp:
  case IPFIX_mplsTopLabelType:
  case IPFIX_minimumTtl:
  case IPFIX_maximumTtl:
  case IPFIX_tcpControlBits:
  case IPFIX_flowEndReason:
    return IPFIX_octet;
  case IPFIX_paddingOctets:
    return IPFIX_octetArray;
  case IPFIX_flowLabelIPv6:
  case IPFIX_payloadLengthIPv6:
  case IPFIX_tcpSequenceNumber:
  case IPFIX_tcpAcknowledgementNumber:
  case IPFIX_mplsTopLabelTtl:
  case IPFIX_mplsLabelStackDepth:
  case IPFIX_mplsLabelStackLength:
  case IPFIX_mplsPayloadLength:
  case IPFIX_mplsTopLabelStackEntry:
  case IPFIX_mplsLabelStackEntry2:
  case IPFIX_mplsLabelStackEntry3:
  case IPFIX_mplsLabelStackEntry4:
  case IPFIX_mplsLabelStackEntry5:
  case IPFIX_mplsLabelStackEntry6:
  case IPFIX_mplsLabelStackEntry7:
  case IPFIX_mplsLabelStackEntry8:
  case IPFIX_mplsLabelStackEntry9:
  case IPFIX_mplsLabelStackEntry10:
  case IPFIX_ipv4Options:
  case IPFIX_ipv6ExtensionHeaders:
  case IPFIX_flowStartDeltaMicroSeconds:
  case IPFIX_flowEndDeltaMicroSeconds:
  case IPFIX_flowStartSysUpTime:
  case IPFIX_flowEndSysUpTime:
  case IPFIX_flowDurationMilliSeconds:
  case IPFIX_flowDurationMicroSeconds:
  case IPFIX_lineCardId:
  case IPFIX_portId:
  case IPFIX_ingressInterface:
  case IPFIX_egressInterface:
  case IPFIX_meteringProcessId:
  case IPFIX_exportingProcessId:
  case IPFIX_flowId:
  case IPFIX_sourceId:
    return IPFIX_unsigned32;
  case IPFIX_flowStartMilliSeconds:
  case IPFIX_flowEndMilliSeconds:
  case IPFIX_systemInitTimeMilliSeconds:
    return IPFIX_dateTimeMilliSeconds;
  case IPFIX_flowStartSeconds:
  case IPFIX_flowEndSeconds:
    return IPFIX_dateTimeSeconds;
  case IPFIX_flowStartMicroSeconds:
  case IPFIX_flowEndMicroSeconds:
    return IPFIX_dateTimeMicroSeconds;
  case IPFIX_ipPayloadLength:
  case IPFIX_tcpOptions:
  case IPFIX_octetDeltaCount:
  case IPFIX_postOctetDeltaCount:
  case IPFIX_octetDeltaSumOfSquares:
  case IPFIX_octetTotalCount:
  case IPFIX_postOctetTotalCount:
  case IPFIX_octetTotalSumOfSquares:
  case IPFIX_packetDeltaCount:
  case IPFIX_postPacketDeltaCount:
  case IPFIX_packetTotalCount:
  case IPFIX_postPacketTotalCount:
  case IPFIX_droppedOctetDeltaCount:
  case IPFIX_droppedPacketDeltaCount:
  case IPFIX_droppedOctetTotalCount:
  case IPFIX_droppedPacketTotalCount:
  case IPFIX_postMCastPacketDeltaCount:
  case IPFIX_postMCastOctetDeltaCount:
  case IPFIX_postMCastPacketTotalCount:
  case IPFIX_postMCastOctetTotalCount:
  case IPFIX_exportedMessageTotalCount:
  case IPFIX_exportedOctetTotalCount:
  case IPFIX_exportedFlowTotalCount:
  case IPFIX_observedFlowTotalCount:
  case IPFIX_ignoredPacketTotalCount:
  case IPFIX_ignoredOctetTotalCount:
  case IPFIX_notSentFlowTotalCount:
  case IPFIX_notSentPacketTotalCount:
  case IPFIX_notSentOctetTotalCount:
  case IPFIX_flowKeyIndicator:
    return IPFIX_unsigned64;
  case IPFIX_sourceIPv6Address:
  case IPFIX_sourceIPv6Prefix:
  case IPFIX_destinationIPv6Address:
  case IPFIX_destinationIPv6Prefix:
  case IPFIX_ipNextHopIPv6Address:
  case IPFIX_bgpNextHopIPv6Address:
  case IPFIX_mplsTopLabelIPv6Address:
  case IPFIX_exporterIPv6Address:
    return IPFIX_ipv6Address;
  }
  return IPFIX_unknown;
}

static inline const char *
ipfix_name(uint16_t type) {
  switch (type) {
  case IPFIX_octetDeltaCount: return "octetDeltaCount";
  case IPFIX_packetDeltaCount: return "packetDeltaCount";
  case IPFIX_protocolIdentifier: return "protocolIdentifier";
  case IPFIX_classOfServiceIPv4: return "classOfServiceIPv4";
  case IPFIX_tcpControlBits: return "tcpControlBits";
  case IPFIX_sourceTransportPort: return "sourceTransportPort";
  case IPFIX_sourceIPv4Address: return "sourceIPv4Address";
  case IPFIX_sourceIPv4Mask: return "sourceIPv4Mask";
  case IPFIX_ingressInterface: return "ingressInterface";
  case IPFIX_destinationTransportPort: return "destinationTransportPort";
  case IPFIX_destinationIPv4Address: return "destinationIPv4Address";
  case IPFIX_destinationIPv4Mask: return "destinationIPv4Mask";
  case IPFIX_egressInterface: return "egressInterface";
  case IPFIX_ipNextHopIPv4Address: return "ipNextHopIPv4Address";
  case IPFIX_bgpSourceAsNumber: return "bgpSourceAsNumber";
  case IPFIX_bgpDestinationAsNumber: return "bgpDestinationAsNumber";
  case IPFIX_bgpNextHopIPv4Address: return "bgpNextHopIPv4Address";
  case IPFIX_postMCastPacketDeltaCount: return "postMCastPacketDeltaCount";
  case IPFIX_postMCastOctetDeltaCount: return "postMCastOctetDeltaCount";
  case IPFIX_flowEndSysUpTime: return "flowEndSysUpTime";
  case IPFIX_flowStartSysUpTime: return "flowStartSysUpTime";
  case IPFIX_postOctetDeltaCount: return "postOctetDeltaCount";
  case IPFIX_postPacketDeltaCount: return "postPacketDeltaCount";
  case IPFIX_minimumPacketLength: return "minimumPacketLength";
  case IPFIX_maximumPacketLength: return "maximumPacketLength";
  case IPFIX_sourceIPv6Address: return "sourceIPv6Address";
  case IPFIX_destinationIPv6Address: return "destinationIPv6Address";
  case IPFIX_sourceIPv6Mask: return "sourceIPv6Mask";
  case IPFIX_destinationIPv6Mask: return "destinationIPv6Mask";
  case IPFIX_flowLabelIPv6: return "flowLabelIPv6";
  case IPFIX_icmpTypeCodeIPv4: return "icmpTypeCodeIPv4";
  case IPFIX_igmpType: return "igmpType";
  case IPFIX_flowActiveTimeOut: return "flowActiveTimeOut";
  case IPFIX_flowInactiveTimeout: return "flowInactiveTimeout";
  case IPFIX_exportedOctetTotalCount: return "exportedOctetTotalCount";
  case IPFIX_exportedMessageTotalCount: return "exportedMessageTotalCount";
  case IPFIX_exportedFlowTotalCount: return "exportedFlowTotalCount";
  case IPFIX_sourceIPv4Prefix: return "sourceIPv4Prefix";
  case IPFIX_destinationIPv4Prefix: return "destinationIPv4Prefix";
  case IPFIX_mplsTopLabelType: return "mplsTopLabelType";
  case IPFIX_mplsTopLabelIPv4Address: return "mplsTopLabelIPv4Address";
  case IPFIX_minimumTtl: return "minimumTtl";
  case IPFIX_maximumTtl: return "maximumTtl";
  case IPFIX_identificationIPv4: return "identificationIPv4";
  case IPFIX_postClassOfServiceIPv4: return "postClassOfServiceIPv4";
  case IPFIX_sourceMacAddress: return "sourceMacAddress";
  case IPFIX_postDestinationMacAddr: return "postDestinationMacAddr";
  case IPFIX_vlanId: return "vlanId";
  case IPFIX_postVlanId: return "postVlanId";
  case IPFIX_ipVersion: return "ipVersion";
  case IPFIX_ipNextHopIPv6Address: return "ipNextHopIPv6Address";
  case IPFIX_bgpNextHopIPv6Address: return "bgpNextHopIPv6Address";
  case IPFIX_ipv6ExtensionHeaders: return "ipv6ExtensionHeaders";
  case IPFIX_mplsTopLabelStackEntry: return "mplsTopLabelStackEntry";
  case IPFIX_mplsLabelStackEntry2: return "mplsLabelStackEntry2";
  case IPFIX_mplsLabelStackEntry3: return "mplsLabelStackEntry3";
  case IPFIX_mplsLabelStackEntry4: return "mplsLabelStackEntry4";
  case IPFIX_mplsLabelStackEntry5: return "mplsLabelStackEntry5";
  case IPFIX_mplsLabelStackEntry6: return "mplsLabelStackEntry6";
  case IPFIX_mplsLabelStackEntry7: return "mplsLabelStackEntry7";
  case IPFIX_mplsLabelStackEntry8: return "mplsLabelStackEntry8";
  case IPFIX_mplsLabelStackEntry9: return "mplsLabelStackEntry9";
  case IPFIX_mplsLabelStackEntry10: return "mplsLabelStackEntry10";
  case IPFIX_destinationMacAddress: return "destinationMacAddress";
  case IPFIX_postSourceMacAddress: return "postSourceMacAddress";
  case IPFIX_interfaceName: return "interfaceName";
  case IPFIX_interfaceDescription: return "interfaceDescription";
  case IPFIX_samplerName: return "samplerName";
  case IPFIX_octetTotalCount: return "octetTotalCount";
  case IPFIX_packetTotalCount: return "packetTotalCount";
  case IPFIX_fragmentOffsetIPv4: return "fragmentOffsetIPv4";
  case IPFIX_bgpNextAdjacentAsNumber: return "bgpNextAdjacentAsNumber";
  case IPFIX_bgpPrevAdjacentAsNumber: return "bgpPrevAdjacentAsNumber";
  case IPFIX_exporterIPv4Address: return "exporterIPv4Address";
  case IPFIX_exporterIPv6Address: return "exporterIPv6Address";
  case IPFIX_droppedOctetDeltaCount: return "droppedOctetDeltaCount";
  case IPFIX_droppedPacketDeltaCount: return "droppedPacketDeltaCount";
  case IPFIX_droppedOctetTotalCount: return "droppedOctetTotalCount";
  case IPFIX_droppedPacketTotalCount: return "droppedPacketTotalCount";
  case IPFIX_flowEndReason: return "flowEndReason";
  case IPFIX_classOfServiceIPv6: return "classOfServiceIPv6";
  case IPFIX_postClassOfServiceIPv6: return "postClassOfServiceIPv6";
  case IPFIX_icmpTypeCodeIPv6: return "icmpTypeCodeIPv6";
  case IPFIX_mplsTopLabelIPv6Address: return "mplsTopLabelIPv6Address";
  case IPFIX_lineCardId: return "lineCardId";
  case IPFIX_portId: return "portId";
  case IPFIX_meteringProcessId: return "meteringProcessId";
  case IPFIX_exportingProcessId: return "exportingProcessId";
  case IPFIX_templateId: return "templateId";
  case IPFIX_wlanChannelId: return "wlanChannelId";
  case IPFIX_wlanSsid: return "wlanSsid";
  case IPFIX_flowId: return "flowId";
  case IPFIX_sourceId: return "sourceId";
  case IPFIX_flowStartSeconds: return "flowStartSeconds";
  case IPFIX_flowEndSeconds: return "flowEndSeconds";
  case IPFIX_flowStartMilliSeconds: return "flowStartMilliSeconds";
  case IPFIX_flowEndMilliSeconds: return "flowEndMilliSeconds";
  case IPFIX_flowStartMicroSeconds: return "flowStartMicroSeconds";
  case IPFIX_flowEndMicroSeconds: return "flowEndMicroSeconds";
  case IPFIX_flowStartNanoSeconds: return "flowStartNanoSeconds";
  case IPFIX_flowEndNanoSeconds: return "flowEndNanoSeconds";
  case IPFIX_flowStartDeltaMicroSeconds: return "flowStartDeltaMicroSeconds";
  case IPFIX_flowEndDeltaMicroSeconds: return "flowEndDeltaMicroSeconds";
  case IPFIX_systemInitTimeMilliSeconds: return "systemInitTimeMilliSeconds";
  case IPFIX_flowDurationMilliSeconds: return "flowDurationMilliSeconds";
  case IPFIX_flowDurationMicroSeconds: return "flowDurationMicroSeconds";
  case IPFIX_observedFlowTotalCount: return "observedFlowTotalCount";
  case IPFIX_ignoredPacketTotalCount: return "ignoredPacketTotalCount";
  case IPFIX_ignoredOctetTotalCount: return "ignoredOctetTotalCount";
  case IPFIX_notSentFlowTotalCount: return "notSentFlowTotalCount";
  case IPFIX_notSentPacketTotalCount: return "notSentPacketTotalCount";
  case IPFIX_notSentOctetTotalCount: return "notSentOctetTotalCount";
  case IPFIX_destinationIPv6Prefix: return "destinationIPv6Prefix";
  case IPFIX_sourceIPv6Prefix: return "sourceIPv6Prefix";
  case IPFIX_postOctetTotalCount: return "postOctetTotalCount";
  case IPFIX_postPacketTotalCount: return "postPacketTotalCount";
  case IPFIX_flowKeyIndicator: return "flowKeyIndicator";
  case IPFIX_postMCastPacketTotalCount: return "postMCastPacketTotalCount";
  case IPFIX_postMCastOctetTotalCount: return "postMCastOctetTotalCount";
  case IPFIX_icmpTypeIPv4: return "icmpTypeIPv4";
  case IPFIX_icmpCodeIPv4: return "icmpCodeIPv4";
  case IPFIX_icmpTypeIPv6: return "icmpTypeIPv6";
  case IPFIX_icmpCodeIPv6: return "icmpCodeIPv6";
  case IPFIX_udpSourcePort: return "udpSourcePort";
  case IPFIX_udpDestinationPort: return "udpDestinationPort";
  case IPFIX_tcpSourcePort: return "tcpSourcePort";
  case IPFIX_tcpDestinationPort: return "tcpDestinationPort";
  case IPFIX_tcpSequenceNumber: return "tcpSequenceNumber";
  case IPFIX_tcpAcknowledgementNumber: return "tcpAcknowledgementNumber";
  case IPFIX_tcpWindowSize: return "tcpWindowSize";
  case IPFIX_tcpUrgentPointer: return "tcpUrgentPointer";
  case IPFIX_tcpHeaderLength: return "tcpHeaderLength";
  case IPFIX_ipHeaderLength: return "ipHeaderLength";
  case IPFIX_totalLengthIPv4: return "totalLengthIPv4";
  case IPFIX_payloadLengthIPv6: return "payloadLengthIPv6";
  case IPFIX_ipTimeToLive: return "ipTimeToLive";
  case IPFIX_nextHeaderIPv6: return "nextHeaderIPv6";
  case IPFIX_ipClassOfService: return "ipClassOfService";
  case IPFIX_ipDiffServCodePoint: return "ipDiffServCodePoint";
  case IPFIX_ipPrecedence: return "ipPrecedence";
  case IPFIX_fragmentFlagsIPv4: return "fragmentFlagsIPv4";
  case IPFIX_octetDeltaSumOfSquares: return "octetDeltaSumOfSquares";
  case IPFIX_octetTotalSumOfSquares: return "octetTotalSumOfSquares";
  case IPFIX_mplsTopLabelTtl: return "mplsTopLabelTtl";
  case IPFIX_mplsLabelStackLength: return "mplsLabelStackLength";
  case IPFIX_mplsLabelStackDepth: return "mplsLabelStackDepth";
  case IPFIX_mplsTopLabelExp: return "mplsTopLabelExp";
  case IPFIX_ipPayloadLength: return "ipPayloadLength";
  case IPFIX_udpMessageLength: return "udpMessageLength";
  case IPFIX_isMulticast: return "isMulticast";
  case IPFIX_internetHeaderLengthIPv4: return "internetHeaderLengthIPv4";
  case IPFIX_ipv4Options: return "ipv4Options";
  case IPFIX_tcpOptions: return "tcpOptions";
  case IPFIX_paddingOctets: return "paddingOctets";
  case IPFIX_headerLengthIPv4: return "headerLengthIPv4";
  case IPFIX_mplsPayloadLength: return "mplsPayloadLength";
  }
  return "unknown";
}

static inline uint16_t
ipfix_type(const char *name) {
  if (0) { }
  else if (strcmp(name, "octetDeltaCount") == 0) { return IPFIX_octetDeltaCount; }
  else if (strcmp(name, "packetDeltaCount") == 0) { return IPFIX_packetDeltaCount; }
  else if (strcmp(name, "protocolIdentifier") == 0) { return IPFIX_protocolIdentifier; }
  else if (strcmp(name, "classOfServiceIPv4") == 0) { return IPFIX_classOfServiceIPv4; }
  else if (strcmp(name, "tcpControlBits") == 0) { return IPFIX_tcpControlBits; }
  else if (strcmp(name, "sourceTransportPort") == 0) { return IPFIX_sourceTransportPort; }
  else if (strcmp(name, "sourceIPv4Address") == 0) { return IPFIX_sourceIPv4Address; }
  else if (strcmp(name, "sourceIPv4Mask") == 0) { return IPFIX_sourceIPv4Mask; }
  else if (strcmp(name, "ingressInterface") == 0) { return IPFIX_ingressInterface; }
  else if (strcmp(name, "destinationTransportPort") == 0) { return IPFIX_destinationTransportPort; }
  else if (strcmp(name, "destinationIPv4Address") == 0) { return IPFIX_destinationIPv4Address; }
  else if (strcmp(name, "destinationIPv4Mask") == 0) { return IPFIX_destinationIPv4Mask; }
  else if (strcmp(name, "egressInterface") == 0) { return IPFIX_egressInterface; }
  else if (strcmp(name, "ipNextHopIPv4Address") == 0) { return IPFIX_ipNextHopIPv4Address; }
  else if (strcmp(name, "bgpSourceAsNumber") == 0) { return IPFIX_bgpSourceAsNumber; }
  else if (strcmp(name, "bgpDestinationAsNumber") == 0) { return IPFIX_bgpDestinationAsNumber; }
  else if (strcmp(name, "bgpNextHopIPv4Address") == 0) { return IPFIX_bgpNextHopIPv4Address; }
  else if (strcmp(name, "postMCastPacketDeltaCount") == 0) { return IPFIX_postMCastPacketDeltaCount; }
  else if (strcmp(name, "postMCastOctetDeltaCount") == 0) { return IPFIX_postMCastOctetDeltaCount; }
  else if (strcmp(name, "flowEndSysUpTime") == 0) { return IPFIX_flowEndSysUpTime; }
  else if (strcmp(name, "flowStartSysUpTime") == 0) { return IPFIX_flowStartSysUpTime; }
  else if (strcmp(name, "postOctetDeltaCount") == 0) { return IPFIX_postOctetDeltaCount; }
  else if (strcmp(name, "postPacketDeltaCount") == 0) { return IPFIX_postPacketDeltaCount; }
  else if (strcmp(name, "minimumPacketLength") == 0) { return IPFIX_minimumPacketLength; }
  else if (strcmp(name, "maximumPacketLength") == 0) { return IPFIX_maximumPacketLength; }
  else if (strcmp(name, "sourceIPv6Address") == 0) { return IPFIX_sourceIPv6Address; }
  else if (strcmp(name, "destinationIPv6Address") == 0) { return IPFIX_destinationIPv6Address; }
  else if (strcmp(name, "sourceIPv6Mask") == 0) { return IPFIX_sourceIPv6Mask; }
  else if (strcmp(name, "destinationIPv6Mask") == 0) { return IPFIX_destinationIPv6Mask; }
  else if (strcmp(name, "flowLabelIPv6") == 0) { return IPFIX_flowLabelIPv6; }
  else if (strcmp(name, "icmpTypeCodeIPv4") == 0) { return IPFIX_icmpTypeCodeIPv4; }
  else if (strcmp(name, "igmpType") == 0) { return IPFIX_igmpType; }
  else if (strcmp(name, "flowActiveTimeOut") == 0) { return IPFIX_flowActiveTimeOut; }
  else if (strcmp(name, "flowInactiveTimeout") == 0) { return IPFIX_flowInactiveTimeout; }
  else if (strcmp(name, "exportedOctetTotalCount") == 0) { return IPFIX_exportedOctetTotalCount; }
  else if (strcmp(name, "exportedMessageTotalCount") == 0) { return IPFIX_exportedMessageTotalCount; }
  else if (strcmp(name, "exportedFlowTotalCount") == 0) { return IPFIX_exportedFlowTotalCount; }
  else if (strcmp(name, "sourceIPv4Prefix") == 0) { return IPFIX_sourceIPv4Prefix; }
  else if (strcmp(name, "destinationIPv4Prefix") == 0) { return IPFIX_destinationIPv4Prefix; }
  else if (strcmp(name, "mplsTopLabelType") == 0) { return IPFIX_mplsTopLabelType; }
  else if (strcmp(name, "mplsTopLabelIPv4Address") == 0) { return IPFIX_mplsTopLabelIPv4Address; }
  else if (strcmp(name, "minimumTtl") == 0) { return IPFIX_minimumTtl; }
  else if (strcmp(name, "maximumTtl") == 0) { return IPFIX_maximumTtl; }
  else if (strcmp(name, "identificationIPv4") == 0) { return IPFIX_identificationIPv4; }
  else if (strcmp(name, "postClassOfServiceIPv4") == 0) { return IPFIX_postClassOfServiceIPv4; }
  else if (strcmp(name, "sourceMacAddress") == 0) { return IPFIX_sourceMacAddress; }
  else if (strcmp(name, "postDestinationMacAddr") == 0) { return IPFIX_postDestinationMacAddr; }
  else if (strcmp(name, "vlanId") == 0) { return IPFIX_vlanId; }
  else if (strcmp(name, "postVlanId") == 0) { return IPFIX_postVlanId; }
  else if (strcmp(name, "ipVersion") == 0) { return IPFIX_ipVersion; }
  else if (strcmp(name, "ipNextHopIPv6Address") == 0) { return IPFIX_ipNextHopIPv6Address; }
  else if (strcmp(name, "bgpNextHopIPv6Address") == 0) { return IPFIX_bgpNextHopIPv6Address; }
  else if (strcmp(name, "ipv6ExtensionHeaders") == 0) { return IPFIX_ipv6ExtensionHeaders; }
  else if (strcmp(name, "mplsTopLabelStackEntry") == 0) { return IPFIX_mplsTopLabelStackEntry; }
  else if (strcmp(name, "mplsLabelStackEntry2") == 0) { return IPFIX_mplsLabelStackEntry2; }
  else if (strcmp(name, "mplsLabelStackEntry3") == 0) { return IPFIX_mplsLabelStackEntry3; }
  else if (strcmp(name, "mplsLabelStackEntry4") == 0) { return IPFIX_mplsLabelStackEntry4; }
  else if (strcmp(name, "mplsLabelStackEntry5") == 0) { return IPFIX_mplsLabelStackEntry5; }
  else if (strcmp(name, "mplsLabelStackEntry6") == 0) { return IPFIX_mplsLabelStackEntry6; }
  else if (strcmp(name, "mplsLabelStackEntry7") == 0) { return IPFIX_mplsLabelStackEntry7; }
  else if (strcmp(name, "mplsLabelStackEntry8") == 0) { return IPFIX_mplsLabelStackEntry8; }
  else if (strcmp(name, "mplsLabelStackEntry9") == 0) { return IPFIX_mplsLabelStackEntry9; }
  else if (strcmp(name, "mplsLabelStackEntry10") == 0) { return IPFIX_mplsLabelStackEntry10; }
  else if (strcmp(name, "destinationMacAddress") == 0) { return IPFIX_destinationMacAddress; }
  else if (strcmp(name, "postSourceMacAddress") == 0) { return IPFIX_postSourceMacAddress; }
  else if (strcmp(name, "interfaceName") == 0) { return IPFIX_interfaceName; }
  else if (strcmp(name, "interfaceDescription") == 0) { return IPFIX_interfaceDescription; }
  else if (strcmp(name, "samplerName") == 0) { return IPFIX_samplerName; }
  else if (strcmp(name, "octetTotalCount") == 0) { return IPFIX_octetTotalCount; }
  else if (strcmp(name, "packetTotalCount") == 0) { return IPFIX_packetTotalCount; }
  else if (strcmp(name, "fragmentOffsetIPv4") == 0) { return IPFIX_fragmentOffsetIPv4; }
  else if (strcmp(name, "bgpNextAdjacentAsNumber") == 0) { return IPFIX_bgpNextAdjacentAsNumber; }
  else if (strcmp(name, "bgpPrevAdjacentAsNumber") == 0) { return IPFIX_bgpPrevAdjacentAsNumber; }
  else if (strcmp(name, "exporterIPv4Address") == 0) { return IPFIX_exporterIPv4Address; }
  else if (strcmp(name, "exporterIPv6Address") == 0) { return IPFIX_exporterIPv6Address; }
  else if (strcmp(name, "droppedOctetDeltaCount") == 0) { return IPFIX_droppedOctetDeltaCount; }
  else if (strcmp(name, "droppedPacketDeltaCount") == 0) { return IPFIX_droppedPacketDeltaCount; }
  else if (strcmp(name, "droppedOctetTotalCount") == 0) { return IPFIX_droppedOctetTotalCount; }
  else if (strcmp(name, "droppedPacketTotalCount") == 0) { return IPFIX_droppedPacketTotalCount; }
  else if (strcmp(name, "flowEndReason") == 0) { return IPFIX_flowEndReason; }
  else if (strcmp(name, "classOfServiceIPv6") == 0) { return IPFIX_classOfServiceIPv6; }
  else if (strcmp(name, "postClassOfServiceIPv6") == 0) { return IPFIX_postClassOfServiceIPv6; }
  else if (strcmp(name, "icmpTypeCodeIPv6") == 0) { return IPFIX_icmpTypeCodeIPv6; }
  else if (strcmp(name, "mplsTopLabelIPv6Address") == 0) { return IPFIX_mplsTopLabelIPv6Address; }
  else if (strcmp(name, "lineCardId") == 0) { return IPFIX_lineCardId; }
  else if (strcmp(name, "portId") == 0) { return IPFIX_portId; }
  else if (strcmp(name, "meteringProcessId") == 0) { return IPFIX_meteringProcessId; }
  else if (strcmp(name, "exportingProcessId") == 0) { return IPFIX_exportingProcessId; }
  else if (strcmp(name, "templateId") == 0) { return IPFIX_templateId; }
  else if (strcmp(name, "wlanChannelId") == 0) { return IPFIX_wlanChannelId; }
  else if (strcmp(name, "wlanSsid") == 0) { return IPFIX_wlanSsid; }
  else if (strcmp(name, "flowId") == 0) { return IPFIX_flowId; }
  else if (strcmp(name, "sourceId") == 0) { return IPFIX_sourceId; }
  else if (strcmp(name, "flowStartSeconds") == 0) { return IPFIX_flowStartSeconds; }
  else if (strcmp(name, "flowEndSeconds") == 0) { return IPFIX_flowEndSeconds; }
  else if (strcmp(name, "flowStartMilliSeconds") == 0) { return IPFIX_flowStartMilliSeconds; }
  else if (strcmp(name, "flowEndMilliSeconds") == 0) { return IPFIX_flowEndMilliSeconds; }
  else if (strcmp(name, "flowStartMicroSeconds") == 0) { return IPFIX_flowStartMicroSeconds; }
  else if (strcmp(name, "flowEndMicroSeconds") == 0) { return IPFIX_flowEndMicroSeconds; }
  else if (strcmp(name, "flowStartNanoSeconds") == 0) { return IPFIX_flowStartNanoSeconds; }
  else if (strcmp(name, "flowEndNanoSeconds") == 0) { return IPFIX_flowEndNanoSeconds; }
  else if (strcmp(name, "flowStartDeltaMicroSeconds") == 0) { return IPFIX_flowStartDeltaMicroSeconds; }
  else if (strcmp(name, "flowEndDeltaMicroSeconds") == 0) { return IPFIX_flowEndDeltaMicroSeconds; }
  else if (strcmp(name, "systemInitTimeMilliSeconds") == 0) { return IPFIX_systemInitTimeMilliSeconds; }
  else if (strcmp(name, "flowDurationMilliSeconds") == 0) { return IPFIX_flowDurationMilliSeconds; }
  else if (strcmp(name, "flowDurationMicroSeconds") == 0) { return IPFIX_flowDurationMicroSeconds; }
  else if (strcmp(name, "observedFlowTotalCount") == 0) { return IPFIX_observedFlowTotalCount; }
  else if (strcmp(name, "ignoredPacketTotalCount") == 0) { return IPFIX_ignoredPacketTotalCount; }
  else if (strcmp(name, "ignoredOctetTotalCount") == 0) { return IPFIX_ignoredOctetTotalCount; }
  else if (strcmp(name, "notSentFlowTotalCount") == 0) { return IPFIX_notSentFlowTotalCount; }
  else if (strcmp(name, "notSentPacketTotalCount") == 0) { return IPFIX_notSentPacketTotalCount; }
  else if (strcmp(name, "notSentOctetTotalCount") == 0) { return IPFIX_notSentOctetTotalCount; }
  else if (strcmp(name, "destinationIPv6Prefix") == 0) { return IPFIX_destinationIPv6Prefix; }
  else if (strcmp(name, "sourceIPv6Prefix") == 0) { return IPFIX_sourceIPv6Prefix; }
  else if (strcmp(name, "postOctetTotalCount") == 0) { return IPFIX_postOctetTotalCount; }
  else if (strcmp(name, "postPacketTotalCount") == 0) { return IPFIX_postPacketTotalCount; }
  else if (strcmp(name, "flowKeyIndicator") == 0) { return IPFIX_flowKeyIndicator; }
  else if (strcmp(name, "postMCastPacketTotalCount") == 0) { return IPFIX_postMCastPacketTotalCount; }
  else if (strcmp(name, "postMCastOctetTotalCount") == 0) { return IPFIX_postMCastOctetTotalCount; }
  else if (strcmp(name, "icmpTypeIPv4") == 0) { return IPFIX_icmpTypeIPv4; }
  else if (strcmp(name, "icmpCodeIPv4") == 0) { return IPFIX_icmpCodeIPv4; }
  else if (strcmp(name, "icmpTypeIPv6") == 0) { return IPFIX_icmpTypeIPv6; }
  else if (strcmp(name, "icmpCodeIPv6") == 0) { return IPFIX_icmpCodeIPv6; }
  else if (strcmp(name, "udpSourcePort") == 0) { return IPFIX_udpSourcePort; }
  else if (strcmp(name, "udpDestinationPort") == 0) { return IPFIX_udpDestinationPort; }
  else if (strcmp(name, "tcpSourcePort") == 0) { return IPFIX_tcpSourcePort; }
  else if (strcmp(name, "tcpDestinationPort") == 0) { return IPFIX_tcpDestinationPort; }
  else if (strcmp(name, "tcpSequenceNumber") == 0) { return IPFIX_tcpSequenceNumber; }
  else if (strcmp(name, "tcpAcknowledgementNumber") == 0) { return IPFIX_tcpAcknowledgementNumber; }
  else if (strcmp(name, "tcpWindowSize") == 0) { return IPFIX_tcpWindowSize; }
  else if (strcmp(name, "tcpUrgentPointer") == 0) { return IPFIX_tcpUrgentPointer; }
  else if (strcmp(name, "tcpHeaderLength") == 0) { return IPFIX_tcpHeaderLength; }
  else if (strcmp(name, "ipHeaderLength") == 0) { return IPFIX_ipHeaderLength; }
  else if (strcmp(name, "totalLengthIPv4") == 0) { return IPFIX_totalLengthIPv4; }
  else if (strcmp(name, "payloadLengthIPv6") == 0) { return IPFIX_payloadLengthIPv6; }
  else if (strcmp(name, "ipTimeToLive") == 0) { return IPFIX_ipTimeToLive; }
  else if (strcmp(name, "nextHeaderIPv6") == 0) { return IPFIX_nextHeaderIPv6; }
  else if (strcmp(name, "ipClassOfService") == 0) { return IPFIX_ipClassOfService; }
  else if (strcmp(name, "ipDiffServCodePoint") == 0) { return IPFIX_ipDiffServCodePoint; }
  else if (strcmp(name, "ipPrecedence") == 0) { return IPFIX_ipPrecedence; }
  else if (strcmp(name, "fragmentFlagsIPv4") == 0) { return IPFIX_fragmentFlagsIPv4; }
  else if (strcmp(name, "octetDeltaSumOfSquares") == 0) { return IPFIX_octetDeltaSumOfSquares; }
  else if (strcmp(name, "octetTotalSumOfSquares") == 0) { return IPFIX_octetTotalSumOfSquares; }
  else if (strcmp(name, "mplsTopLabelTtl") == 0) { return IPFIX_mplsTopLabelTtl; }
  else if (strcmp(name, "mplsLabelStackLength") == 0) { return IPFIX_mplsLabelStackLength; }
  else if (strcmp(name, "mplsLabelStackDepth") == 0) { return IPFIX_mplsLabelStackDepth; }
  else if (strcmp(name, "mplsTopLabelExp") == 0) { return IPFIX_mplsTopLabelExp; }
  else if (strcmp(name, "ipPayloadLength") == 0) { return IPFIX_ipPayloadLength; }
  else if (strcmp(name, "udpMessageLength") == 0) { return IPFIX_udpMessageLength; }
  else if (strcmp(name, "isMulticast") == 0) { return IPFIX_isMulticast; }
  else if (strcmp(name, "internetHeaderLengthIPv4") == 0) { return IPFIX_internetHeaderLengthIPv4; }
  else if (strcmp(name, "ipv4Options") == 0) { return IPFIX_ipv4Options; }
  else if (strcmp(name, "tcpOptions") == 0) { return IPFIX_tcpOptions; }
  else if (strcmp(name, "paddingOctets") == 0) { return IPFIX_paddingOctets; }
  else if (strcmp(name, "headerLengthIPv4") == 0) { return IPFIX_headerLengthIPv4; }
  else if (strcmp(name, "mplsPayloadLength") == 0) { return IPFIX_mplsPayloadLength; }
  else { return 0; }
}

#endif

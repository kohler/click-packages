#ifndef FTPPORTMAPPER6_HH
#define FTPPORTMAPPER6_HH
#include "tcpaddresstranslator.hh"
CLICK_DECLS

/*
 * =c
 * FTPPortMapper6(TCPAddressTranslator)
 * =s TCP
 * Translates FTP control commands.
 * =d
 *
 * Expects FTP control packets. Watches packets for PORT/EPRT, PASV/EPSV commands
 * and their respective responses in IPv4/IPv6 packets. It must be used after after the
 * packets are translated from IPv4 to IPv6 or vice versa, because FTPPortMapper6
 * takes the source address of the packet to replace it in the PORT/EPRT command
 * to be translated. It works like this:
 *
 * Connection from a IPv4 FTP client to a IPv6 FTP Server:
 * - if the client sends a PORT command, it gets translated to a EPRT command. The
 *   the IPv6 address for the EPRT command is taken from the source address field in
 *   the IPv6 header and the port number is taken from the old PORT command.
 *   It's response gets translated too (200 EPRT command successful to 200 PORT command
 *   succesful).
 * - if the client sends a PASV command, it gets translated to a EPSV command. It's
 *   response gets translated too.
 *
 * Connection from a IPv6 FTP client to a IPv4 FTP Server:
 * - if the client sends a EPRT command, it gets translated to a PORT command. The
 *   the IPv4 address for the PORT command is taken from the source address field in
 *   the IPv4 header and the port number is taken from the old EPRT command.
 *   It's response gets translated too(200 PORT command successful to 200 EPRT command
 *   succesful).
 * - if the client sends a EPSV command, it gets translated to PASV command. It's
 *   response gets translated too.
 *
 * This makes FTP possible through a NAT-PT setup.
 *
 * L<RFC 959, File Transfer Protocol (FTP)|http://www.ietf.org/rfc/rfc0959.txt>
 * L<RFC 2428, FTP extensions for IPv6|http://www.ietf.org/rfc/rfc2428.txt>
 * L<RFC 2765, Stateless IP/ICMP Translation Algorithim (SIIT)|http://www.ietf.org/rfc/rfc2765.txt>
 */

class FTPPortMapper6 : public Element {

  TCPAddressTranslator *_tcp_a;

  public:

    FTPPortMapper6();
    ~FTPPortMapper6();

    const char *class_name() const	{ return "FTPPortMapper6"; }
    const char *processing() const	{ return PUSH; }
    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void uninitialize();
    void push(int port, Packet *p);

  private:
    bool epsv_found;
    void translate_ipv6_ipv4(Packet *p);
    void translate_ipv4_ipv6(Packet *p);

};

CLICK_ENDDECLS
#endif

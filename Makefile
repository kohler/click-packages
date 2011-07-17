# Warning: this file must be usable by regular make
# (unlike the Makefiles in subdirectories).

SHELL = /bin/sh


PACKAGE = click-packages
VERSION = 1.8.0

srcdir = .


CLICKDIR = $(HOME)/click
SUBDIRS = dhcp iias models multicast netflow roofnet security snmp unibo_qos
IP6_SUBDIRS = ip6_natpt multicast6

distdir = $(PACKAGE)-$(VERSION)

all install clean distclean:
	for d in $(SUBDIRS); do { cd $$d; $(MAKE) $@ || exit 1; cd ..; }; done
	if click-buildtool provides ip6; then for d in $(IP6_SUBDIRS); do { cd $$d; $(MAKE) $@ || exit 1; cd ..; }; done; fi

recheck:
	for d in $(SUBDIRS) $(IP6_SUBDIRS); do { cd $$d; ./config.status --recheck; ./config.status; cd ..; }; done

dist: distdir
	tar czf $(distdir).tar.gz $(distdir)
	-rm -rf $(distdir)
distdir:
	for d in $(SUBDIRS); do { cd $$d; autoconf; cd ..; }; done
	cp $(CLICKDIR)/LICENSE .
	-rm -rf $(distdir)
	mkdir $(distdir)
	chmod 777 $(distdir)
	for file in `cat $(srcdir)/DISTFILES | grep .`; do \
	  if expr "$$file" : '.*:$$' >/dev/null 2>&1; then \
	    d=`echo $$file | sed 's/:$$//;s/^\.\///'`; \
	  elif test -d "$(srcdir)/$$d/$$file"; then \
	    mkdir $(distdir)/$$d/$$file; \
	    chmod 777 $(distdir)/$$d/$$file; \
	  else \
	    for f in `cd $(srcdir)/$$d && echo $$file`; do \
	      test -f "$(distdir)/$$d/$$f" \
	      || ln $(srcdir)/$$d/$$f $(distdir)/$$d/$$f 2> /dev/null \
	      || cp -p $(srcdir)/$$d/$$f $(distdir)/$$d/$$f \
	      || echo "Could not copy $$d/$$f!" 1>&2; \
	  done; fi; \
	done


.PHONY: all always elemlist elemlists \
	bsdmodule exopc linuxmodule ns tools userlevel \
	clean distclean dist distdir recheck \
	install install-doc install-man install-local install-include install-local-include \
	uninstall uninstall-local uninstall-local-include

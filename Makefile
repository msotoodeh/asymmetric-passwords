# 
#   env RELEASE=1 make clean demo
#
#   make libs               build libraries
#
#   make demo               create library and demo file
#

.PHONY: all clean distclean libs demo archive

all: demo

libs: 
	$(MAKE) -C common
	$(MAKE) -C client
	$(MAKE) -C server

demo: libs
	$(MAKE) -C demo demo

clean: 
	$(MAKE) -C common clean
	$(MAKE) -C client clean
	$(MAKE) -C server clean
	$(MAKE) -C demo clean

distclean:
	$(MAKE) -C demo distclean
	$(MAKE) -C common distclean
	$(MAKE) -C client distclean
	$(MAKE) -C server distclean
	@rm -rf build32/ build64/

archive: distclean
	tar cvf /tmp/asymmpass-`date '+%Y%m%d'`-src.tar *


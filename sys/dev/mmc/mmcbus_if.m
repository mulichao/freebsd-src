#-
# Copyright (c) 2006 M. Warner Losh
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD: src/sys/dev/mmc/mmcbus_if.m,v 1.1.2.1 2006/11/20 07:16:28 imp Exp $
#

#include <dev/mmc/mmcreg.h>
#include <dev/mmc/bridge.h>

#
# This is the set of callbacks that mmc bridges call into the bus, or
# that mmc/sd card drivers call to make requests.
#

INTERFACE mmcbus;

#
# Queue and wait for a request.
#
METHOD int wait_for_request {
	device_t	brdev;
	device_t	reqdev;
	struct mmc_request *req;
};

#
# Claim the current bridge, blocking the current thread until the host
# is no longer busy.
#
METHOD int acquire_bus {
	device_t	brdev;
	device_t	reqdev;
}

#
# Release the current bridge.
#
METHOD int release_bus {
	device_t	brdev;
	device_t	reqdev;
}

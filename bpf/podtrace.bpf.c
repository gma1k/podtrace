// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"

#include "network.c"
#include "filesystem.c"
#include "cpu.c"
#include "memory.c"
#include "syscalls.c"
#include "resources.c"
#include "database.c"
#include "redis.c"
#include "memcached.c"
#include "kafka.c"
#include "fastcgi.c"
#include "grpc.c"

char LICENSE[] SEC("license") = "GPL";

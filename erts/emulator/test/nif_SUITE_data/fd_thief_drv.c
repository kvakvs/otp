/* ``Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * The Initial Developer of the Original Code is Ericsson Utvecklings AB.
 * Portions created by Ericsson are Copyright 1999, Ericsson Utvecklings
 * AB. All Rights Reserved.''
 * 
 *     $Id$
 */

/*
 * A driver which offers a simple API to steal fd via driver_select from
 * another nif or driver who is selecting it currently.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "erl_driver.h"

static ErlDrvData start(ErlDrvPort port, char* command);

static ErlDrvSSizeT control(ErlDrvData drv_data,
                            unsigned int command, char* buf,
                            ErlDrvSizeT len, char** rbuf, ErlDrvSizeT rlen);

void on_ready_input(ErlDrvData drv_data, ErlDrvEvent event);

static ErlDrvEntry caller_drv_entry = {
    NULL /* init */,
    start,
    NULL /* stop */,
    NULL /* output */,
    on_ready_input /* ready_input */,
    NULL /* ready_output */,
    "fd_thief_drv",
    NULL /* finish */,
    NULL /* handle */,
    control,
    NULL /* timeout */,
    NULL, /* outputv */
    NULL /* ready_async */,
    NULL /* flush */,
    NULL /* call */,
    NULL /* event */,
    ERL_DRV_EXTENDED_MARKER,
    ERL_DRV_EXTENDED_MAJOR_VERSION,
    ERL_DRV_EXTENDED_MINOR_VERSION,
    ERL_DRV_FLAG_USE_PORT_LOCKING,
    NULL /* handle2 */,
    NULL /* handle_monitor */
};

DRIVER_INIT(caller_drv) {
    return &caller_drv_entry;
}

/* Send a tuple {fd_thief, Port, SomeAtom, Pid} to the caller */
void
send_caller(ErlDrvData drv_data, char* atom_str) {
    int res;
    ErlDrvPort port = (ErlDrvPort) drv_data;
    ErlDrvTermData msg[] = {
        ERL_DRV_ATOM, driver_mk_atom("fd_thief"),
        ERL_DRV_PORT, driver_mk_port(port),
        ERL_DRV_ATOM, driver_mk_atom(atom_str),
        ERL_DRV_PID, driver_caller(port),
        ERL_DRV_TUPLE, (ErlDrvTermData) 4
    };
    res = erl_drv_output_term(driver_mk_port(port), msg,
                              sizeof(msg) / sizeof(ErlDrvTermData));
    if (res <= 0) {
        driver_failure_atom(port, "erl_drv_output_term failed");
    }
}

void on_ready_input(ErlDrvData drv_data, ErlDrvEvent event) {
    int fd = (int) (ErlDrvSInt) event;
    unsigned char rd_size;
    char buf[256];

    read(fd, &rd_size, 1);
    read(fd, buf, rd_size);
    buf[rd_size] = 0;

    send_caller(drv_data, buf);
}

static ErlDrvData
start(ErlDrvPort port, char* command) {
    set_port_control_flags(port, PORT_CONTROL_FLAG_BINARY);
    return (ErlDrvData) port;
}

static ErlDrvSInt parse_big_u64(const unsigned char* p) {
    if (sizeof(void*) == 4) {
        return (ErlDrvSInt) p[0] +
               ((ErlDrvSInt) p[1] << 8) +
               ((ErlDrvSInt) p[2] << 16) +
               ((ErlDrvSInt) p[3] << 24);
    }
    return (ErlDrvSInt) p[0] +
           ((ErlDrvSInt) p[1] << 8) +
           ((ErlDrvSInt) p[2] << 16) +
           ((ErlDrvSInt) p[3] << 24) +
           ((ErlDrvSInt) p[4] << 32) +
           ((ErlDrvSInt) p[5] << 40) +
           ((ErlDrvSInt) p[6] << 48) +
           ((ErlDrvSInt) p[7] << 56);

}

/* Synchronous erlang:port_control BIF comes here */
static ErlDrvSSizeT
control(ErlDrvData drv_data,
        unsigned int command, char* buf,
        ErlDrvSizeT len, char** rbuf, ErlDrvSizeT rlen) {
    ErlDrvPort port = (ErlDrvPort) drv_data;
    ErlDrvSSizeT result = 0;
    switch (command) {
        case 's': { /* s requests the driver to call select and steal the fd */
            if (len < sizeof(void*)) {
                return -1;
            }
            ErlDrvSInt fd = parse_big_u64((const unsigned char*)buf);
            driver_select(port, (ErlDrvEvent) fd, DO_READ, 1);
            send_caller(drv_data, "done");
        }
        default:
            break;
    }
    return result;
}

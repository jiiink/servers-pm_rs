#include "inc.h"

void rupdate_clear_upds() {
    struct rprocupd *rpupd;
    while ((rpupd = rupdate.first_rpupd)) {
        rupdate.first_rpupd = rpupd->next_rpupd;
        rupdate_upd_clear(rpupd);
    }
    RUPDATE_CLEAR();
}

void rupdate_add_upd(struct rprocupd* rpupd) {
    struct rprocupd *prev_rpupd = NULL, **link;
    endpoint_t ep = rpupd->rp->r_pub->endpoint;

    assert(!rpupd->next_rpupd && !rpupd->prev_rpupd);

    for (link = &rupdate.first_rpupd; 
         *link && (*link)->rp->r_pub->endpoint != RS_PROC_NR; 
         link = &(*link)->next_rpupd);

    if (ep != RS_PROC_NR) {
        link = &rupdate.last_rpupd->next_rpupd;
        if (rupdate.last_rpupd->rp->r_pub->endpoint == RS_PROC_NR)
            prev_rpupd = rupdate.last_rpupd;
    }
    
    rpupd->next_rpupd = *link;
    if (*link) (*link)->prev_rpupd = rpupd;
    *link = rpupd;
    if (!rpupd->next_rpupd) rupdate.last_rpupd = rpupd;

    rupdate.num_rpupds++;

    int lu_flags = rpupd->lu_flags & (SEF_LU_INCLUDES_VM|SEF_LU_INCLUDES_RS|SEF_LU_MULTI);
    if(lu_flags) {
        struct rprocupd *walk_rpupd = rupdate.first_rpupd;
        while (walk_rpupd) {
            walk_rpupd->lu_flags |= lu_flags;
            walk_rpupd->init_flags |= lu_flags;
            walk_rpupd = walk_rpupd->next_rpupd;
        }
    }

    if(!rupdate.vm_rpupd && (lu_flags & SEF_LU_INCLUDES_VM)) {
        rupdate.vm_rpupd = rpupd;
    } else if(!rupdate.rs_rpupd && (lu_flags & SEF_LU_INCLUDES_RS)) {
        rupdate.rs_rpupd = rpupd;
    }
}

void rupdate_set_new_upd_flags(struct rprocupd* rpupd) {
    int lu_flags = 0;

    if (rupdate.num_rpupds > 0) {
        rpupd->lu_flags |= SEF_LU_MULTI;
        rpupd->init_flags |= SEF_LU_MULTI;
    }

    if (rupdate.last_rpupd) {
        lu_flags = rupdate.last_rpupd->lu_flags & (SEF_LU_INCLUDES_VM|SEF_LU_INCLUDES_RS);
        rpupd->lu_flags |= lu_flags;
        rpupd->init_flags |= lu_flags;
    }

    if (UPD_IS_PREPARING_ONLY(rpupd)) return;

    endpoint_t ep = rpupd->rp->r_pub->endpoint;
    if (ep == VM_PROC_NR) {
        rpupd->lu_flags |= SEF_LU_INCLUDES_VM;
        rpupd->init_flags |= SEF_LU_INCLUDES_VM;
    } else if (ep == RS_PROC_NR) {
        rpupd->lu_flags |= SEF_LU_INCLUDES_RS;
        rpupd->init_flags |= SEF_LU_INCLUDES_RS;
    }
}

void rupdate_upd_clear(struct rprocupd* rpupd) {
    if(rpupd->rp->r_new_rp)
        cleanup_service(rpupd->rp->r_new_rp);
    
    if(rpupd->prepare_state_data_gid != GRANT_INVALID)
        cpf_revoke(rpupd->prepare_state_data_gid);
    
    if(rpupd->prepare_state_data.size > 0) {
        if(rpupd->prepare_state_data.ipcf_els_gid != GRANT_INVALID)
            cpf_revoke(rpupd->prepare_state_data.ipcf_els_gid);
        if(rpupd->prepare_state_data.eval_gid != GRANT_INVALID)
            cpf_revoke(rpupd->prepare_state_data.eval_gid);
        free(rpupd->prepare_state_data.ipcf_els);
        free(rpupd->prepare_state_data.eval_addr);
    }
    rupdate_upd_init(rpupd, NULL);
}

void request_prepare_update_service_debug(char *file, int line, struct rproc *rp, int state) {
    message m;
    int no_reply;

    if(state != SEF_LU_STATE_NULL) {
        struct rprocupd *rpupd = &rp->r_upd;
        rpupd->prepare_tm = getticks();
        rp->r_flags |= RS_UPDATING;
        if(!UPD_IS_PREPARING_ONLY(rpupd)) {
            assert(rp->r_new_rp);
            rp->r_new_rp->r_flags |= RS_UPDATING;
        } else assert(!rp->r_new_rp);

        m.m_rs_update.flags = rpupd->lu_flags;
        m.m_rs_update.state_data_gid = rpupd->prepare_state_data_gid;
    }

    m.m_type = RS_LU_PREPARE;
    m.m_rs_update.state = state;
    no_reply = !(rp->r_flags & RS_PREPARE_DONE);
    rs_asynsend(rp, &m, no_reply);
}

int srv_update(endpoint_t src_e, endpoint_t dst_e, int sys_upd_flags) {
    if (src_e == VM_PROC_NR) {
        return sys_update(src_e, dst_e, sys_upd_flags & SF_VM_ROLLBACK ? SYS_UPD_ROLLBACK : 0);
    } else if (!RUPDATE_IS_UPD_VM_MULTI() || RUPDATE_IS_VM_INIT_DONE()) {
        return vm_update(src_e, dst_e, sys_upd_flags);
    }
    return OK;
}

int update_service(struct rproc **src_rpp, struct rproc **dst_rpp, int swap_flag, int sys_upd_flags) {
    int r;
    struct rproc *src_rp = *src_rpp, *dst_rp = *dst_rpp;
    int pid = src_rp->r_pid;
    endpoint_t endpoint = src_rp->r_pub->endpoint;

    if (swap_flag == RS_SWAP) {
        r = srv_update(src_rp->r_pub->endpoint, dst_rp->r_pub->endpoint, sys_upd_flags);
        if (r != OK) return r;
    }

    swap_slot(&src_rp, &dst_rp);

    src_rp->r_pid = dst_rp->r_pid;
    src_rp->r_pub->endpoint = dst_rp->r_pub->endpoint;
    rproc_ptr[_ENDPOINT_P(src_rp->r_pub->endpoint)] = src_rp;
    dst_rp->r_pid = pid;
    dst_rp->r_pub->endpoint = endpoint;
    rproc_ptr[_ENDPOINT_P(dst_rp->r_pub->endpoint)] = dst_rp;

    sys_getpriv(&src_rp->r_priv, src_rp->r_pub->endpoint);
    sys_getpriv(&dst_rp->r_priv, dst_rp->r_pub->endpoint);

    *src_rpp = src_rp;
    *dst_rpp = dst_rp;

    activate_service(dst_rp, src_rp);

    return OK;
}

void rollback_service(struct rproc **new_rpp, struct rproc **old_rpp) {
    struct rproc *rp;
    int r = OK;

    if ((*old_rpp)->r_pub->endpoint == RS_PROC_NR) {
        r = sys_whoami(NULL, NULL, 0, NULL, NULL);
        if (r == OK && sys_whoami(NULL, NULL, 0, NULL, NULL) != RS_PROC_NR) {
            r = vm_update((*new_rpp)->r_pub->endpoint, (*old_rpp)->r_pub->endpoint, SF_VM_ROLLBACK);
        }
    } else {
        int swap_flag = ((*new_rpp)->r_flags & RS_INIT_PENDING ? RS_DONTSWAP : RS_SWAP);
        if (swap_flag == RS_SWAP) 
            sys_privctl((*new_rpp)->r_pub->endpoint, SYS_PRIV_DISALLOW, NULL);
        r = update_service(new_rpp, old_rpp, swap_flag, SF_VM_ROLLBACK);
    }
}

void update_period(message *m_ptr) {
    struct rprocupd *rpupd = rupdate.curr_rpupd;
    clock_t now = m_ptr->m_notify.timestamp;

    if ((rpupd->prepare_maxtime > 0) && (now - rpupd->prepare_tm > rpupd->prepare_maxtime)) {
        end_update(EINTR, RS_CANCEL);
    }
}

int start_update_prepare(int allow_retries) {
    if (!RUPDATE_IS_UPD_SCHEDULED()) 
        return EINVAL;

    if (!rs_is_idle()) {
        if (!allow_retries) 
            abort_update_proc(EAGAIN);
        return EAGAIN;
    }

    if (start_update_prepare_next() == NULL) {
        end_update(OK, RS_REPLY);
        return ESRCH;
    }

    return OK;
}

struct rprocupd* start_update_prepare_next() {
    struct rprocupd *rpupd;

    if (!RUPDATE_IS_UPDATING())
        rpupd = rupdate.first_rpupd;
    else
        rpupd = rupdate.curr_rpupd->next_rpupd;

    if (!rpupd)
        return NULL;

    rupdate.flags |= RS_UPDATING;
    do {
        rupdate.curr_rpupd = rpupd;
        request_prepare_update_service(rupdate.curr_rpupd->rp, rupdate.curr_rpupd->prepare_state);
        if (!UPD_IS_PREPARING_ONLY(rpupd))
            break;
    } while ((rpupd = rpupd->next_rpupd));

    return rpupd;
}

int start_update() {
    assert(RUPDATE_IS_UPDATING());
    assert(rupdate.num_rpupds > 0);
    assert(rupdate.first_rpupd);
    assert(rupdate.last_rpupd);
    assert(rupdate.curr_rpupd == rupdate.last_rpupd);

    if (RUPDATE_IS_UPD_VM_MULTI()) {
        RUPDATE_ITER(rupdate.first_rpupd, struct rprocupd *prev_rpupd, struct rprocupd *rpupd,
            if (!UPD_IS_PREPARING_ONLY(rpupd)) {
                struct rproc *rp = rpupd->rp;
                struct rproc *new_rp = rp->r_new_rp;
                rp->r_pub->old_endpoint = rpupd->state_endpoint;
                rp->r_pub->new_endpoint = rp->r_pub->endpoint;
                rp->r_pub->sys_flags |= SF_VM_UPDATE;
                if (rpupd->lu_flags & SEF_LU_NOMMAP)
                    rp->r_pub->sys_flags |= SF_VM_NOMMAP;
            }
        );
    }

    if (start_update_prepare_next() == NULL) {
        end_update(OK, RS_REPLY);
        return ESRCH;
    }

    return OK;
}

int start_srv_update(struct rprocupd *rpupd) {
    struct rproc *old_rp = rpupd->rp, *new_rp = old_rp->r_new_rp;
    int r, sys_upd_flags = 0;

    rupdate.num_init_ready_pending++;
    new_rp->r_flags |= RS_INITIALIZING;
    new_rp->r_flags |= RS_INIT_PENDING;
    if (rpupd->lu_flags & SEF_LU_NOMMAP) 
        sys_upd_flags |= SF_VM_NOMMAP;

    if (old_rp->r_pub->endpoint != RS_PROC_NR) {
        r = update_service(&old_rp, &new_rp, RS_SWAP, sys_upd_flags);
        if (r != OK) {
            end_update(r, RS_REPLY);
            return r;
        }
    }

    return OK;
}

void end_srv_update(struct rprocupd *rpupd, int result, int reply_flag) {
    struct rproc *old_rp = rpupd->rp, *new_rp = old_rp->r_new_rp, *surviving_rp, *exiting_rp;

    if (result == OK) {
        surviving_rp = new_rp;
        exiting_rp = old_rp;
    } else {
        surviving_rp = old_rp;
        exiting_rp = new_rp;
    }

    surviving_rp->r_flags &= ~(RS_UPDATING|RS_PREPARE_DONE|RS_INIT_PENDING);
    surviving_rp->r_check_tm = 0;
    surviving_rp->r_alive_tm = getticks();

    rpupd->rp = surviving_rp;
    old_rp->r_new_rp = NULL;
    new_rp->r_old_rp = NULL;

    if (reply_flag == RS_REPLY) {
        message m;
        m.m_type = result;
        reply(surviving_rp->r_pub->endpoint, surviving_rp, &m);
    } else if (reply_flag == RS_CANCEL) {
        if (!(surviving_rp->r_flags & RS_TERMINATED))
            request_prepare_update_service(surviving_rp, SEF_LU_STATE_NULL);
    }

    struct rproc *rps[2] = {exiting_rp};
    int nr_rps = 1;
    if (rpupd->lu_flags & SEF_LU_DETACHED) {
        rps[1] = exiting_rp;
        nr_rps = 2;
    }

    for (int i = 0; i < nr_rps; i++) {
        if (rps[i] == old_rp && (rpupd->lu_flags & SEF_LU_DETACHED)) {
            message m;
            m.m_type = EDEADEPT;
            rps[i]->r_flags |= RS_CLEANUP_DETACH;
            cleanup_service(rps[i]);
            reply(rps[i]->r_pub->endpoint, rps[i], &m);
        } else {
            cleanup_service(rps[i]);
        }
    }

    if (rps[0]->r_pub->endpoint == VM_PROC_NR && RUPDATE_IS_UPD_MULTI()) 
        reply_flag = RS_CANCEL;
}

void end_update_rev_iter(int result, int reply_flag, struct rprocupd *skip_rpupd, struct rprocupd *only_rpupd) {
    RUPDATE_REV_ITER(rupdate.last_rpupd, struct rprocupd *prev_rpupd, struct rprocupd *rpupd,
        if (!UPD_IS_PREPARING_ONLY(rpupd) && (!skip_rpupd || rpupd != skip_rpupd) && (!only_rpupd || rpupd == only_rpupd)) {
            if (rpupd == rupdate.curr_rpupd) 
                end_update_curr(rpupd, result, reply_flag);
            else 
                end_update_prepare_done(rpupd, result);
        }
    );
}

void end_update_curr(struct rprocupd *rpupd, int result, int reply_flag) {
    struct rproc *old_rp = rpupd->rp, *new_rp = old_rp->r_new_rp;
    assert(old_rp && new_rp);

    if (result != OK && SRV_IS_UPDATING_AND_INITIALIZING(new_rp) && rpupd != rupdate.rs_rpupd) {
        rollback_service(&new_rp, &old_rp);
    }
    end_srv_update(rpupd, result, reply_flag);
}

void end_update_before_prepare(struct rprocupd *rpupd, int result) {
    struct rproc *old_rp = rpupd->rp, *new_rp = old_rp->r_new_rp;
    assert(old_rp && new_rp);
    cleanup_service(new_rp);
}

void end_update_prepare_done(struct rprocupd *rpupd, int result) {
    assert(!RUPDATE_IS_INITIALIZING());
    assert(!(rpupd->rp->r_flags & RS_INITIALIZING));

    end_srv_update(rpupd, result, RS_REPLY);
}

void end_update_initializing(struct rprocupd *rpupd, int result) {
    struct rproc *old_rp = rpupd->rp, *new_rp = old_rp->r_new_rp;
    assert(old_rp && new_rp);

    if (result != OK && rpupd != rupdate.rs_rpupd)
        rollback_service(&new_rp, &old_rp);

    end_srv_update(rpupd, result, RS_REPLY);
}

void end_update_debug(char *file, int line, int result, int reply_flag) {
    RUPDATE_ITER(rupdate.first_rpupd, struct rprocupd *prev_rpupd, struct rprocupd *rpupd,

        if (UPD_IS_PREPARING_ONLY(rpupd))
            request_prepare_update_service(rpupd->rp, SEF_LU_STATE_NULL);

        rpupd->rp->r_flags &= ~RS_PREPARE_DONE;
    );

    end_update_rev_iter(result, reply_flag, rupdate.vm_rpupd, NULL);
    if (rupdate.vm_rpupd) 
        end_update_rev_iter(result, reply_flag, NULL, rupdate.vm_rpupd);

    RUPDATE_ITER(rupdate.first_rpupd, struct rprocupd *prev_rpupd, struct rprocupd *rpupd,
        if (prev_rpupd) 
            rupdate_upd_clear(prev_rpupd);

        if (result == OK && !UPD_IS_PREPARING_ONLY(rpupd))
            end_srv_update(rpupd, result, reply_flag);
    );

    rupdate_upd_clear(rupdate.last_rpupd);
    RUPDATE_CLEAR();
}

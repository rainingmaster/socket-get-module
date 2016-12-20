#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define BUFFER_SIZE 1024


static void *ngx_http_sock_get_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_sock_get_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_socket_get(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_sock_get_handler(ngx_http_request_t *r);


/* location config struct */
typedef struct {
    ngx_array_t     *handler_args;
    ngx_int_t        status;
} ngx_http_sock_get_loc_conf_t;

typedef struct {
    struct sockaddr_in  servaddr;
    ngx_str_t           content;
    ngx_uint_t          timeout;
} ngx_http_sock_get_args_t;

typedef struct {
    ngx_chain_t     *in;
    unsigned         header_sent:1;
} ngx_http_sock_get_ctx_t;

char buffer[BUFFER_SIZE];



static ngx_command_t ngx_http_sock_get_args[] = {

    { ngx_string("socket_get"),
      NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_socket_get,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_sock_get_module_ctx = {
    NULL,                                       /* preconfiguration */
    NULL,                                       /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_sock_get_create_loc_conf,          /* create location configuration */
    ngx_http_sock_get_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_sock_get_module = {
    NGX_MODULE_V1,
    &ngx_http_sock_get_module_ctx,       /* module context */
    ngx_http_sock_get_args,              /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_sock_get_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_sock_get_loc_conf_t        *sglcf;

    sglcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sock_get_loc_conf_t));
    if (sglcf == NULL) {
        return NULL;
    }

    /* set by ngx_pcalloc
     *  sglcf->handler_args = NULL
     */

    sglcf->status = NGX_CONF_UNSET;

    return sglcf;
}


static char *
ngx_http_sock_get_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sock_get_loc_conf_t    *prev = parent;
    ngx_http_sock_get_loc_conf_t    *conf = child;

    if (conf->handler_args == NULL) {
        conf->handler_args = prev->handler_args;
    }

    ngx_conf_merge_value(conf->status, prev->status, 200);

    return NGX_CONF_OK;
}


static char *
ngx_http_socket_get(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *value;
    ngx_http_sock_get_loc_conf_t   *sglcf = conf;
    ngx_http_sock_get_args_t       *args;
    ngx_array_t                   **args_ptr;
    ngx_http_core_loc_conf_t        *clcf;
    ngx_int_t                        port;
    u_char                          *host;

    args_ptr = &(sglcf->handler_args);
    if (*args_ptr == NULL) {
        *args_ptr = ngx_array_create(cf->pool, 1,
                                     sizeof(ngx_http_sock_get_args_t));

        if (*args_ptr == NULL) {
            return NGX_CONF_ERROR;
        }

        clcf = ngx_http_conf_get_module_loc_conf(cf,
                                                 ngx_http_core_module);

        clcf->handler = ngx_http_sock_get_handler;

    }

    args = ngx_array_push(*args_ptr);

    value = cf->args->elts;

    /* we skip the first arg and start from the second */
    host = value[1].data;
    port = ngx_atoi(value[2].data, value[2].len);

    args->servaddr.sin_family = AF_INET;
    args->servaddr.sin_port = htons(port);
    args->servaddr.sin_addr.s_addr = inet_addr((char *) host);

    if (cf->args->nelts > 3) {
        args->content = value[3];

        if (cf->args->nelts > 4) {
            args->timeout = ngx_atoi(value[4].data, value[4].len);
        }
    }

    return NGX_CONF_OK;
}

/* some utils */
ngx_int_t
ngx_http_sock_get_send_chain_link(ngx_http_request_t *r,
    ngx_http_sock_get_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_int_t                       rc;
    ngx_http_sock_get_loc_conf_t   *sglcf;

    if (!r->header_sent && !ctx->header_sent) {
        sglcf = ngx_http_get_module_loc_conf(r, ngx_http_sock_get_module);

        r->headers_out.status = (ngx_uint_t) sglcf->status;

        if (ngx_http_set_content_type(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_clear_content_length(r);
        ngx_http_clear_accept_ranges(r);

        rc = ngx_http_send_header(r);
        ctx->header_sent = 1;

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    if (in == NULL) {

#if defined(nginx_version) && nginx_version <= 8004

        /* earlier versions of nginx does not allow subrequests
            to send last_buf themselves */
        if (r != r->main) {
            return NGX_OK;
        }

#endif

        rc = ngx_http_send_special(r, NGX_HTTP_LAST);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_OK;
    }

    /* FIXME we should udpate chains to recycle chain links and bufs */
    return ngx_http_output_filter(r, in);
}


ngx_http_sock_get_ctx_t *
ngx_http_sock_get_create_ctx(ngx_http_request_t *r)
{
    ngx_http_sock_get_ctx_t         *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_sock_get_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    return ctx;
}


/* handlers */
void
ngx_http_sock_finalize_connection(ngx_connection_t *c, ngx_int_t rc)
{
    if (ngx_del_conn) {
        ngx_del_conn(c, 0);
    } else {
        ngx_del_event(c->write, NGX_READ_EVENT, 0);
    }
    if (c->fd > 0) {
        ngx_close_socket(c->fd);
    }

    ngx_http_finalize_request((ngx_http_request_t *) c->data, rc);
}


static void
ngx_http_sock_read_handler(ngx_event_t *ev)
{
    ngx_int_t                       len;
    ngx_int_t                       rc;
    u_char                         *s;
    ngx_http_sock_get_ctx_t        *ctx;
    ngx_connection_t               *c;
    ngx_http_request_t             *r;
    ngx_buf_t                      *buf;
    ngx_chain_t                   **ll;
    ngx_chain_t                    *cl;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *)c->data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_sock_get_module);

    len = recv(c->fd, buffer, BUFFER_SIZE, 0);
    if (len <= 0) {
        /* finish and send content */
        if (ctx->in) {
            rc = ngx_http_sock_get_send_chain_link(r, ctx, ctx->in);
        }

        rc = ngx_http_sock_get_send_chain_link(r, ctx, NULL /* indicate LAST */);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ngx_http_sock_finalize_connection(c, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (!r->request_body) {
            if (ngx_http_discard_request_body(r) != NGX_OK) {
                ngx_http_sock_finalize_connection(c, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        ngx_http_sock_finalize_connection(c, NGX_DONE);
        return;
    }

    s = ngx_palloc(r->pool, len);
    if (s == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "[http socket] ngx_palloc() failed");
        ngx_http_sock_finalize_connection(c, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    dd("buffer is %s", buffer);
    dd("s is %s", s);

    ngx_memmove(s, buffer, len);

    buf = ngx_create_temp_buf(r->pool, len);
    if (buf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "[http socket] ngx_create_temp_buf() failed");
        ngx_http_sock_finalize_connection(c, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    buf->start = buf->pos = s;
    buf->last = buf->end = s + len;
    buf->memory = 1;

    for (cl = ctx->in, ll = &(ctx->in); cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "[http socket] ngx_alloc_chain_link() failed");
        return;
    }

    cl->buf = buf;
    cl->next = NULL;
    *ll = cl;

    return;
}


ngx_int_t
ngx_http_sock_read(ngx_http_request_t *r, ngx_int_t sockfd)
{
    u_char                          *p = NULL;
    ngx_connection_t                *c;
    ngx_event_t                     *rev;

    p = ngx_palloc(r->pool, sizeof(ngx_connection_t) + sizeof(ngx_event_t));
    if (p == NULL) {
        return NGX_ERROR;
    }

    c = (ngx_connection_t *)p;

    p += sizeof(ngx_connection_t);
    rev = (ngx_event_t *) p;

    c->fd = sockfd;
    c->error = 0;
    c->read = rev;
    c->write = rev;
    c->data = r;
    c->log = r->connection->log;

    rev->active = 0;
    rev->data = c;
    rev->handler = ngx_http_sock_read_handler;
    rev->log = r->connection->log;
    if (ngx_add_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno, "[http socket] ngx_add_event() failed");
        return NGX_ERROR;
    }

    r->count++;

    return NGX_OK;
}


ngx_int_t
ngx_http_sock_get_run_args(ngx_http_request_t *r, ngx_http_sock_get_args_t *arg)
{
    ngx_int_t                       sockfd;
    ngx_int_t                       rc;

    sockfd = ngx_socket(AF_INET, SOCK_STREAM, 0);
    rc = connect(sockfd, (struct sockaddr *)&(arg->servaddr), sizeof(arg->servaddr));
    if (rc < 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno, "[http socket] connect() failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (arg->content.data) {
        if (send(sockfd, arg->content.data, arg->content.len, 0) == -1) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno, "[http socket] send() failed");
            ngx_close_socket(sockfd);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ngx_http_sock_read(r, sockfd);

    return NGX_DONE;
}


ngx_int_t
ngx_http_sock_get_handler(ngx_http_request_t *r)
{
    ngx_http_sock_get_loc_conf_t   *sglcf;
    ngx_array_t                    *args;
    size_t                         i;
    ngx_int_t                      rc;
    ngx_http_sock_get_args_t       *arg;
    ngx_http_sock_get_args_t       *arg_elts;
    ngx_http_sock_get_ctx_t        *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_sock_get_module);
    if (ctx == NULL) {
        ctx = ngx_http_sock_get_create_ctx(r);
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_sock_get_module);
    }

    sglcf = ngx_http_get_module_loc_conf(r, ngx_http_sock_get_module);
    args = sglcf->handler_args;
    arg_elts = args->elts;

    for (i = 0; i < args->nelts; i++) {
        arg = &arg_elts[i];
        rc = ngx_http_sock_get_run_args(r, arg);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
    }

    return NGX_OK;
}

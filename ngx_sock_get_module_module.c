#include <ngx_config.h>
#include <ngx_core.h>


static void *ngx_http_sock_get_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_sock_get_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static void *ngx_http_sock_get_create_main_conf(ngx_conf_t *cf);

static char *ngx_http_socket_get(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_sock_get_handler(ngx_http_request_t *r);


typedef struct {
    ngx_array_t     *shm_zones;
} ngx_http_sock_get_main_conf_t;

/* location config struct */
typedef struct {
    ngx_array_t     *handler_cmds;

    ngx_int_t        status;
} ngx_http_sock_get_loc_conf_t;

typedef struct {
    ngx_str_t     host;
    ngx_uint_t    port;
    ngx_str_t     content;
    ngx_uint_t    timeout;
} ngx_http_sock_get_args_t;



static ngx_command_t ngx_http_sock_get_cmds[] = {

    { ngx_string("socket_get"),
      NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_socket_get,
      0,
      0,
      NULL },

    ngx_null_command
};


static ngx_stream_module_t  ngx_http_sock_get_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_http_sock_get_init,                     /* postconfiguration */

    ngx_http_sock_get_create_main_conf,         /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_sock_get_create_loc_conf,          /* create location configuration */
    ngx_http_sock_get_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_sock_get_module_module = {
    NGX_MODULE_V1,
    &ngx_http_sock_get_module_ctx,       /* module context */
    ngx_http_sock_get_cmds,              /* module directives */
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


typedef struct {
    ngx_str_t   name;
    size_t      size;
    ngx_int_t   isold;
    ngx_int_t   isinit;
} ngx_http_sock_get_ctx_t;


static void *
ngx_http_sock_get_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_sock_get_main_conf_t    *sgmcf;

    sgmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sock_get_main_conf_t));
    if (sgmcf == NULL) {
        return NULL;
    }

    /* set by ngx_pcalloc:
     *      hmcf->requires_filter = 0;
     */

    return sgmcf;
}


static void *
ngx_http_sock_get_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_sock_get_loc_conf_t        *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sock_get_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* set by ngx_pcalloc
     *  conf->handler_cmds = NULL
     */

    conf->status = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_sock_get_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sock_get_loc_conf_t    *prev = parent;
    ngx_http_sock_get_loc_conf_t    *conf = child;

    if (conf->handler_cmds == NULL) {
        conf->handler_cmds = prev->handler_cmds;
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
    ngx_array_t                   **cmds_ptr;
    ngx_http_core_loc_conf_t        *clcf;

    cmds_ptr = &(sglcf->handler_cmds);
    if (*cmds_ptr == NULL) {
        *cmds_ptr = ngx_array_create(cf->pool, 1,
                                     sizeof(ngx_http_sock_get_args_t));

        if (*cmds_ptr == NULL) {
            return NGX_CONF_ERROR;
        }

        clcf = ngx_http_conf_get_module_loc_conf(cf,
                                                 ngx_http_core_module);

        clcf->handler = ngx_http_sock_get_handler;

    }

    args = ngx_array_push(*cmds_ptr);

    value = cf->args->elts;

    /* we skip the first arg and start from the second */

    args->host = value[1];
    args->port = ngx_atoi(value[2].data, value[2].len);
    
    if (cf->args->nelts > 2) {
        args->content = value[3];
        
        if (cf->args->nelts > 3) {
            args->timeout = ngx_atoi(value[4].data, value[4].len);
        }
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_sock_get_handler(ngx_http_request_t *r)
{
    ngx_int_t       len;
    ngx_int_t       result;
    ngx_int_t       sockfd;
    char           *c

    gethostbyname((char *) host);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address;
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "server_socket");
    setsockopt(sockfd)

    result = connect(sockfd, (struct sockaddr *)&address, sizeof(address));
    if(result == -1)
    {
        perror("connect failed: ");
        exit(1);
    }

    char c = 'A';
    write(sockfd, &c, 1);
    len = read(sockfd, &c, 1);

    close(sockfd);

    rc = ngx_http_echo_send_chain_link(r, ctx, NULL /* indicate LAST */);

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (!r->request_body) {
        if (ngx_http_discard_request_body(r) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

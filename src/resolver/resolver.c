#include "resolver.h"
#include "../helpers/selector.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

#define MAX_HOSTNAME 256
#define MAX_PORT 16

struct resolver_job {
    struct selector_key *key;
    char hostname[MAX_HOSTNAME];
    char port[MAX_PORT];
    resolver_done_callback callback;
    void *data;
    
    enum resolver_status status;
    struct addrinfo *result;
    
    struct resolver_job *next;
};

struct job_queue {
    struct resolver_job *head;
    struct resolver_job *tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool shutdown;
};

static struct {
    struct job_queue pending_jobs;
    struct job_queue done_jobs;
    pthread_t *threads;
    int num_threads;
    int notification_fd[2];
    bool initialized;
} resolver_ctx = {
    .initialized = false
};

// ============================================================================
// Funciones auxiliares de cola
// ============================================================================

static void queue_init(struct job_queue *q) {
    q->head = NULL;
    q->tail = NULL;
    q->shutdown = false;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
}

static void queue_destroy(struct job_queue *q) {
    pthread_mutex_lock(&q->mutex);
    while (q->head) {
        struct resolver_job *job = q->head;
        q->head = job->next;
        if (job->result) {
            freeaddrinfo(job->result);
        }
        free(job);
    }
    q->shutdown = true;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->mutex);
    
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
}

static void queue_push(struct job_queue *q, struct resolver_job *job) {
    pthread_mutex_lock(&q->mutex);
    
    job->next = NULL;
    if (q->tail) {
        q->tail->next = job;
    } else {
        q->head = job;
    }
    q->tail = job;
    
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}

static struct resolver_job* queue_pop(struct job_queue *q) {
    pthread_mutex_lock(&q->mutex);
    
    while (!q->head && !q->shutdown) {
        pthread_cond_wait(&q->cond, &q->mutex);
    }
    
    struct resolver_job *job = NULL;
    if (q->head) {
        job = q->head;
        q->head = job->next;
        if (!q->head) {
            q->tail = NULL;
        }
    }
    
    pthread_mutex_unlock(&q->mutex);
    return job;
}

// ============================================================================
// Worker thread
// ============================================================================

static void* resolver_worker(void *arg) {
    (void)arg;
    
    while (true) {
        struct resolver_job *job = queue_pop(&resolver_ctx.pending_jobs);
        if (!job) {
            break;
        }
        
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        
        struct addrinfo *result = NULL;
        int gai_error = getaddrinfo(job->hostname, job->port, &hints, &result);
        
        if (gai_error == 0 && result != NULL) {
            job->status = RESOLVER_SUCCESS;
            job->result = result;
        } else {
            job->status = RESOLVER_FAILED;
            job->result = NULL;
            if (result) {
                freeaddrinfo(result);
            }
        }
        
        queue_push(&resolver_ctx.done_jobs, job);
        
        char notify = '!';
        ssize_t written = write(resolver_ctx.notification_fd[1], &notify, 1);
        (void)written;
    }
    
    return NULL;
}

// ============================================================================
// Handler para el notification FD en el selector
// ============================================================================

static void resolver_notification_read(struct selector_key *key) {
    char buf[256];
    while (read(key->fd, buf, sizeof(buf)) > 0) {
    }
    
    while (true) {
        pthread_mutex_lock(&resolver_ctx.done_jobs.mutex);
        struct resolver_job *job = resolver_ctx.done_jobs.head;
        if (job) {
            resolver_ctx.done_jobs.head = job->next;
            if (!resolver_ctx.done_jobs.head) {
                resolver_ctx.done_jobs.tail = NULL;
            }
        }
        pthread_mutex_unlock(&resolver_ctx.done_jobs.mutex);
        
        if (!job) {
            break;
        }
        
        if (job->callback) {
            job->callback(job->key, job->status, job->result, job->data);
        } else {
            if (job->result) {
                freeaddrinfo(job->result);
            }
        }
        
        free(job);
    }
}

static const struct fd_handler resolver_notification_handler = {
    .handle_read = resolver_notification_read,
    .handle_write = NULL,
    .handle_block = NULL,
    .handle_close = NULL,
};

// ============================================================================
// API Pública
// ============================================================================

bool resolver_init(int num_threads) {
    if (resolver_ctx.initialized) {
        return false;
    }
    
    if (num_threads < 1 || num_threads > 4) {
        num_threads = 2;
    }
    
    if (pipe(resolver_ctx.notification_fd) == -1) {
        return false;
    }
    
    int flags = fcntl(resolver_ctx.notification_fd[0], F_GETFL, 0);
    if (flags == -1 || fcntl(resolver_ctx.notification_fd[0], F_SETFL, flags | O_NONBLOCK) == -1) {
        close(resolver_ctx.notification_fd[0]);
        close(resolver_ctx.notification_fd[1]);
        return false;
    }
    
    queue_init(&resolver_ctx.pending_jobs);
    queue_init(&resolver_ctx.done_jobs);
    
    resolver_ctx.num_threads = num_threads;
    resolver_ctx.threads = calloc((size_t)num_threads, sizeof(pthread_t));
    if (!resolver_ctx.threads) {
        close(resolver_ctx.notification_fd[0]);
        close(resolver_ctx.notification_fd[1]);
        queue_destroy(&resolver_ctx.pending_jobs);
        queue_destroy(&resolver_ctx.done_jobs);
        return false;
    }
    
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&resolver_ctx.threads[i], NULL, resolver_worker, NULL) != 0) {
            resolver_ctx.num_threads = i;
            resolver_destroy();
            return false;
        }
    }
    
    resolver_ctx.initialized = true;
    return true;
}

bool resolver_register_notification_fd(fd_selector selector) {
    if (!resolver_ctx.initialized) {
        return false;
    }
    
    selector_status st = selector_register(
        selector,
        resolver_ctx.notification_fd[0],
        &resolver_notification_handler,
        OP_READ,
        NULL
    );
    
    return st == SELECTOR_SUCCESS;
}

bool resolver_request(
    struct selector_key *key,
    const char *hostname,
    const char *port,
    resolver_done_callback callback,
    void *data
) {
    if (!resolver_ctx.initialized || !hostname || !port) {
        return false;
    }
    
    struct resolver_job *job = calloc(1, sizeof(*job));
    if (!job) {
        return false;
    }
    
    job->key = key;
    strncpy(job->hostname, hostname, MAX_HOSTNAME - 1);
    job->hostname[MAX_HOSTNAME - 1] = '\0';
    strncpy(job->port, port, MAX_PORT - 1);
    job->port[MAX_PORT - 1] = '\0';
    job->callback = callback;
    job->data = data;
    job->status = RESOLVER_PENDING;
    job->result = NULL;
    
    queue_push(&resolver_ctx.pending_jobs, job);
    
    return true;
}

void resolver_free_result(struct addrinfo *result) {
    if (result) {
        freeaddrinfo(result);
    }
}

void resolver_destroy(void) {
    if (!resolver_ctx.initialized) {
        return;
    }
    
    pthread_mutex_lock(&resolver_ctx.pending_jobs.mutex);
    resolver_ctx.pending_jobs.shutdown = true;
    pthread_cond_broadcast(&resolver_ctx.pending_jobs.cond);
    pthread_mutex_unlock(&resolver_ctx.pending_jobs.mutex);
    
    for (int i = 0; i < resolver_ctx.num_threads; i++) {
        pthread_join(resolver_ctx.threads[i], NULL);
    }
    
    free(resolver_ctx.threads);
    resolver_ctx.threads = NULL;
    
    queue_destroy(&resolver_ctx.pending_jobs);
    queue_destroy(&resolver_ctx.done_jobs);
    
    close(resolver_ctx.notification_fd[0]);
    close(resolver_ctx.notification_fd[1]);
    
    resolver_ctx.initialized = false;
}

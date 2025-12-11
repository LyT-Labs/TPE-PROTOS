#include "metrics.h"
#include <string.h>

static struct socks5_metrics global_metrics = {0};

struct socks5_metrics * metrics_get(void) {
    return &global_metrics;
}

void metrics_reset(void) {
    memset(&global_metrics, 0, sizeof(global_metrics));
}

#include "access_log.h"
#include <stdio.h>
#include <time.h>

void access_log_record(const char *username,
                       const char *src_ip,
                       const char *dst_host,
                       uint16_t dst_port,
                       bool success) {
    FILE *file = fopen("access.log", "a");
    if (file == NULL) {
        return;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    const char *result = success ? "OK" : "FAIL";

    fprintf(file, "%s USER=\"%s\" SRC=\"%s\" DST=\"%s:%u\" RESULT=\"%s\"\n",
            timestamp, username, src_ip, dst_host, dst_port, result);

    fclose(file);
}

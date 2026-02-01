#include "credentials_log.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

void credentials_log_record(const char *protocol,
                             const char *src_ip,
                             const char *dst_host,
                             uint16_t dst_port,
                             const char *username,
                             const char *password) {
    FILE *file = fopen("credentials.log", "a");
    if (file == NULL) {
        return;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(file, "%s PROTO=%s SRC=%s DST=%s:%u USER=%s PASS=%s\n",
            timestamp, protocol, src_ip, dst_host, dst_port,
            username, password);

    fclose(file);
}

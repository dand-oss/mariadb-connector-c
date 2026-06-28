#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <mysql.h>
#include <mariadb_rpl.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 4 || Size > 1024 * 1024) return 0;

  /* 1. Locate the real \xFEbin magic marker inside the payload */
  const uint8_t binlog_magic[4] = {0xFE, 0x62, 0x69, 0x6E};
  const uint8_t *real_start = NULL;
  uint32_t uncompress = 1;
  uint32_t extract = 1;
  uint32_t verify_checksum = 1;

  for (size_t i = 0; i <= Size - 4; i++) {
    if (memcmp(&Data[i], binlog_magic, 4) == 0) {
      real_start = &Data[i];
      Size -= i; /* Recalculate remaining length from this point forward */
      break;
    }
  }

  /* If the payload doesn't contain the binlog magic signature at all, discard it */
  if (!real_start) return 0;

  MARIADB_RPL *rpl = mariadb_rpl_init(NULL);
  if (!rpl) return 0;

  /* 2. Create an anonymous in-memory file descriptor */
  int fd = memfd_create("fuzz_binlog", MFD_CLOEXEC);
  if (fd < 0) {
    mariadb_rpl_close(rpl);
    return 0;
  }

  /* 3. Write only the clean binlog stream starting exactly at \xFEbin */
  if (write(fd, real_start, Size) != (ssize_t)Size) {
    close(fd);
    mariadb_rpl_close(rpl);
    return 0;
  }

  /* 4. Rewind the descriptor so the MariaDB parser reads it from the beginning */
  lseek(fd, 0, SEEK_SET);

  /* 5. Reference the anonymous file using the process's own file descriptor map */
  char proc_filename[64];
  snprintf(proc_filename, sizeof(proc_filename), "/proc/self/fd/%d", fd);

  if (mariadb_rpl_optionsv(rpl, MARIADB_RPL_FILENAME, proc_filename, (size_t)0) == 0 &&
      mariadb_rpl_optionsv(rpl, MARIADB_RPL_UNCOMPRESS, &uncompress) == 0 &&
      mariadb_rpl_optionsv(rpl, MARIADB_RPL_VERIFY_CHECKSUM, &verify_checksum) == 0 &&
      mariadb_rpl_optionsv(rpl, MARIADB_RPL_EXTRACT_VALUES, &extract) == 0) {
    
    if (mariadb_rpl_open(rpl) == 0) {
      MARIADB_RPL_EVENT *event = NULL;
      MARIADB_RPL_EVENT *table_map_event = NULL;

      while ((event = mariadb_rpl_fetch(rpl, NULL))) {
        if (event->event_type == TABLE_MAP_EVENT) {
          if (table_map_event)
            mariadb_free_rpl_event(table_map_event);
          table_map_event = event;
          continue;
        }
        
        if (event->event_type == WRITE_ROWS_EVENT_V1 ||
            event->event_type == UPDATE_ROWS_EVENT_V1 ||
            event->event_type == DELETE_ROWS_EVENT_V1 ||
            event->event_type == WRITE_ROWS_COMPRESSED_EVENT_V1 ||
            event->event_type == UPDATE_ROWS_COMPRESSED_EVENT_V1 ||
            event->event_type == DELETE_ROWS_COMPRESSED_EVENT_V1 ||
            event->event_type == WRITE_ROWS_EVENT ||
            event->event_type == UPDATE_ROWS_EVENT ||
            event->event_type == DELETE_ROWS_EVENT) {

          if (table_map_event) {
            /* This forces libFuzzer straight into your column parsing logic blocks! */
            MARIADB_RPL_ROW *rpl_row = mariadb_rpl_extract_rows(rpl, table_map_event, event);
            if (rpl_row) {
              /* * Freeing the row struct if the API has a specific row release function,
               * or letting mariadb_free_rpl_event clean its root memory pool.
               */
            }
          }
        }
        mariadb_free_rpl_event(event);
      }
      if (table_map_event)
        mariadb_free_rpl_event(table_map_event);
    }
  }

  /* Closing the FD automatically reclaims the memory; no unlink() required. */
  close(fd);
  mariadb_rpl_close(rpl);

  return 0;
}

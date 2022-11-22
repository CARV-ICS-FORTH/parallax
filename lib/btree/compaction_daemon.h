#ifndef COMPACTION_DAEMON_H
#define COMPACTION_DAEMON_H

/**
 * Starts a compaction daemon that is responding for spawing compaction workers
 */
void *compaction_daemon(void *args);

#endif // COMPACTION_DAEMON_H

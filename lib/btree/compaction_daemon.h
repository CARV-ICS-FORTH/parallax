// Copyright [2023] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#ifndef COMPACTION_DAEMON_H
#define COMPACTION_DAEMON_H
#include "btree.h"
#include <pthread.h>
#include <stdbool.h>
struct compaction_daemon;

struct compaction_daemon *compactiond_create(db_handle *handle, bool do_not_issue_L0_compactions);
/**
 * Starts a compaction daemon that is responding for spawing compaction workers
 */
bool compactiond_start(struct compaction_daemon *daemon, pthread_t *context);

void compactiond_notify_all(struct compaction_daemon *daemon);
void compactiond_wait(struct compaction_daemon *daemon);
void compactiond_interrupt(struct compaction_daemon *daemon);
void compactiond_force_compaction(struct compaction_daemon *daemon);

void compactiond_close(struct compaction_daemon *daemon);

#endif // COMPACTION_DAEMON_H

#ifndef PERSISTENT_OPERATIONS_H_
#define PERSISTENT_OPERATIONS_H_

#include <stdint.h>
/**
 * \brief Returns number of garbage entries detected during the recovery of the redo undo log.
 * */
uint32_t get_garbage_entries(void);

/**
 * \brief Returns garbage bytes detected during the recovery of the redo undo log.
 * */
uint32_t get_garbage_bytes(void);

/**
 * \brief Triggers the counting for blobs garbage bytes when recovering redo_undo_log.
 * */
void enable_validation_garbage_bytes(void);

/**
 * \brief Disables the counting for blobs garbage bytes when recovering redo_undo_log.
 * */
void disable_validation_garbage_bytes(void);

#endif // PERSISTENT_OPERATIONS_H_

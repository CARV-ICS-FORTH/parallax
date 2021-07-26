#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <uthash.h>
#include <log.h>
#include "volume_manager.h"
#include "djb2.h"
#define MEM_LOG_WORD_SIZE_IN_BITS 8
#define MEM_WORDS_PER_BITMAP_BLOCK 512

static struct mem_bitmap_word bitmap_get_curr_word(struct volume_descriptor *volume_desc)
{
	return volume_desc->curr_word;
}

static void mem_bitmap_reset_pos(struct volume_descriptor *volume_desc)
{
	volume_desc->curr_word.word_id = 0;
	volume_desc->curr_word.start_bit = 0;
	volume_desc->curr_word.end_bit = 0;
	volume_desc->curr_word.word_addr = volume_desc->mem_volume_bitmap;
}

static struct mem_bitmap_word mem_bitmap_get_next_word(struct volume_descriptor *volume_desc)
{
	struct mem_bitmap_word ret = { .word_id = -1, .word_addr = NULL };

	if (++volume_desc->curr_word.word_id >= volume_desc->mem_volume_bitmap_size) {
		// sorry end of bitmap
		return ret;
	}
	volume_desc->curr_word.start_bit = 0;
	volume_desc->curr_word.end_bit = 0;
	volume_desc->curr_word.word_addr = &volume_desc->mem_volume_bitmap[volume_desc->curr_word.word_id];
	return bitmap_get_curr_word(volume_desc);
}

static uint32_t mem_bitmap_check_first_n_bits_free(struct mem_bitmap_word *b_word, uint32_t length_bits,
						   uint32_t suffix_bits)
{
	uint64_t mask = 0xFFFFFFFFFFFFFFFF;
	int actual_bits;
	if (length_bits - suffix_bits > MEM_WORD_SIZE_IN_BITS) {
		actual_bits = MEM_WORD_SIZE_IN_BITS;
	} else {
		actual_bits = length_bits - suffix_bits;
		uint32_t diff = MEM_WORD_SIZE_IN_BITS - actual_bits;
		if (diff < MEM_WORD_SIZE_IN_BITS)
			mask = mask >> diff;
		else {
			log_fatal("Wrong sliding number!");
			exit(EXIT_FAILURE);
		}
	}
	if (mask == (mask & *b_word->word_addr)) {
		b_word->start_bit = 0;
		b_word->end_bit = actual_bits;
		// log_info("Found First %u bits of word %d in buddy %d", actual_bits,
		// b_word->word_id,
		//	 b_word->buddy_pair);
		return actual_bits;
	} else {
		// log_info("Not Found First %u bits of word %d in buddy %d", actual_bits,
		// b_word->word_id,
		//	 b_word->buddy_pair);
		return 0;
	}
}

static uint32_t mem_bitmap_find_suffix(struct mem_bitmap_word *b_word, uint64_t *rounds, int num_rounds)
{
	uint64_t mask = 0x8000000000000000;
	uint32_t size_bits = 0;
	int L = num_rounds;
	uint64_t b = 1;
	// log_info("Suffix search: num rounds are %d", num_rounds);
	do {
		if (mask & (rounds[L] << size_bits)) {
			size_bits += (b << L);
			// log_info("Suffix now is %u L = %d rounds %llu", size_bits, L,
			// rounds[L]);
		}
		--L;
	} while (L >= 0);
	if (size_bits) {
		b_word->start_bit = MEM_WORD_SIZE_IN_BITS - size_bits;
		b_word->end_bit = MEM_WORD_SIZE_IN_BITS;
		// log_info("Suffix search size found is %u", size_bits);
		return size_bits;
	} else {
		// log_info("Sorry no suffix found");
		return 0;
	}
}

static uint32_t mem_bitmap_find_nbits_in_word(struct mem_bitmap_word *b_word, uint64_t *round, uint32_t *num_rounds,
					      uint32_t length_bits)
{
	uint32_t actual_bits;
	if (length_bits > MEM_WORD_SIZE_IN_BITS)
		actual_bits = MEM_WORD_SIZE_IN_BITS;
	else
		actual_bits = length_bits;

	// log_info("Checking if word %u contains bits %u", b_word->word_id,
	// actual_bits);

	uint32_t m_rounds;
	// calculare upper integral part of log2
	double r = log2(actual_bits);
	m_rounds = (uint64_t)r;
	// check if we have decimal points
	if (floor(r) != r)
		++m_rounds;
	assert(m_rounds + 1 < *num_rounds);
	*num_rounds = m_rounds;
	// log_info("Num rounds are %u", *num_rounds);
	int shift_size = 1;

	// Our guard

	round[0] = *b_word->word_addr;
	//log_info("Round [0] bitmap is %llu",round[0]);
	for (uint32_t i = 0; i < *num_rounds; ++i) {
		if (i == 0)
			shift_size = 1;
		else if (i == *num_rounds - 1)
			shift_size = actual_bits - (shift_size * 2);
		else
			shift_size *= 2;
		// log_info("Shift size %u", shift_size);
		uint64_t c = round[i] << shift_size;
		round[i + 1] = round[i] & c;
	}

	// did we find size or WORD_SIZE bits?
	if (round[*num_rounds] != 0) {
		b_word->end_bit = ffsl(round[*num_rounds]);
		b_word->start_bit = b_word->end_bit - actual_bits;
		//log_info("Yes it does! end bit is %u round is %llu", b_word->end_bit,
		//round[*num_rounds]);

		return actual_bits;
	} else {
		return 0;
	}
}

static void mem_bitmap_mark_reserved(struct mem_bitmap_word *b_word)
{
	struct bitmap_word_byte {
		uint8_t b0 : 1;
		uint8_t b1 : 1;
		uint8_t b2 : 1;
		uint8_t b3 : 1;
		uint8_t b4 : 1;
		uint8_t b5 : 1;
		uint8_t b6 : 1;
		uint8_t b7 : 1;
	};
	struct bitmap_word_byte *word_b = (struct bitmap_word_byte *)b_word->word_addr;
	for (uint32_t bit = b_word->start_bit; bit < b_word->end_bit; ++bit) {
		uint32_t i = bit / 8;
		uint32_t j = bit % 8;
		switch (j) {
		case 0:
			word_b[i].b0 = 0;
			break;
		case 1:
			word_b[i].b1 = 0;
			break;
		case 2:
			word_b[i].b2 = 0;
			break;
		case 3:
			word_b[i].b3 = 0;
			break;
		case 4:
			word_b[i].b4 = 0;
			break;
		case 5:
			word_b[i].b5 = 0;
			break;
		case 6:
			word_b[i].b6 = 0;
			break;
		case 7:
			word_b[i].b7 = 0;
			break;
		}
	}

	return;
}

static uint64_t mem_bitmap_translate_word_to_offt(struct volume_descriptor *volume_desc, struct mem_bitmap_word *b)
{
	if (!b) {
		log_fatal("Null word!");
		assert(0);
		exit(EXIT_FAILURE);
	} else {
		log_info("Word is %u start bit %u end bit %u", b->word_id, b->start_bit, b->end_bit);
		uint64_t bytes_per_word = MEM_WORD_SIZE_IN_BITS * SEGMENT_SIZE;
		uint64_t dev_offt = (bytes_per_word * b->word_id);
		dev_offt += (b->start_bit * SEGMENT_SIZE);
		log_info("Dev offt = %llu", dev_offt);
		dev_offt += volume_desc->my_superblock.volume_metadata_size;
		log_info("Now is Dev offt = %llu volume_metadata_size %llu", dev_offt,
			 volume_desc->my_superblock.volume_metadata_size);
		return dev_offt;
	}
}

uint64_t mem_allocate(struct volume_descriptor *volume_desc, uint64_t num_bytes)
{
	// assert(num_bytes == SEGMENT_SIZE);
	if (num_bytes == 0)
		return 0;
	if (num_bytes % SEGMENT_SIZE != 0) {
		log_warn("Allocation size: %llu not a multiple of SEGMENT_SIZE: %u", num_bytes, SEGMENT_SIZE);
		return 0;
	}

	uint64_t base_addr;

	uint64_t length_bits = num_bytes / SEGMENT_SIZE;

	struct mem_bitmap_word *b_words = NULL;
	/*how many words will i need?*/
	uint32_t alloc_size;
	if (length_bits == 1)
		alloc_size = sizeof(struct mem_bitmap_word);
	else if (length_bits > 1 && length_bits < 64)
		alloc_size = sizeof(struct mem_bitmap_word) * 2;
	else
		alloc_size = ((length_bits / MEM_WORD_SIZE_IN_BITS) * sizeof(struct mem_bitmap_word)) +
			     (2 * sizeof(struct mem_bitmap_word));
	b_words = (struct mem_bitmap_word *)malloc(alloc_size);

	if (b_words == NULL) {
		log_fatal("Malloc failed out of memory");
		exit(EXIT_FAILURE);
	}

	int32_t wrap_around = 0;
	int idx = -1;
	struct mem_bitmap_word b_word = bitmap_get_curr_word(volume_desc);
	uint64_t suffix_bits = 0;

	while (suffix_bits < length_bits) {
		if (b_word.word_addr == NULL) {
			// reached end of bitmap
			if (wrap_around == MAX_ALLOCATION_TRIES) {
				log_warn("Volume %s out of space allocation request size was "
					 "%llu max_tries %d\n",
					 volume_desc->volume_name, num_bytes, MAX_ALLOCATION_TRIES);
				mem_bitmap_reset_pos(volume_desc);
				free(b_words);
				return 0;
			} else {
				++wrap_around;
				if (volume_desc->max_suffix < suffix_bits) /*update max_suffix */
					volume_desc->max_suffix = suffix_bits;
				suffix_bits = 0; /*contiguous bytes just broke :-( */
				idx = -1; /*reset _counters*/
				// reset bitmap pos
				log_warn("\n*****\nEnd Of Bitmap, wrap around\n*****\n");
				mem_bitmap_reset_pos(volume_desc);
				b_word = bitmap_get_curr_word(volume_desc);
				continue;
			}
		} else if (*b_word.word_addr == 0) {
			/*update max_suffix*/
			if (volume_desc->max_suffix < suffix_bits)
				volume_desc->max_suffix = suffix_bits;
			// contiguous bytes just broke :-(
			suffix_bits = 0;
			// reset _counters
			idx = -1;
			b_word = mem_bitmap_get_next_word(volume_desc);
			continue;
		}

		// Are the first bits of word free
		uint32_t bits_found = mem_bitmap_check_first_n_bits_free(&b_word, length_bits, suffix_bits);

		if (bits_found) {
			++idx;
			b_words[idx] = b_word;
			suffix_bits += bits_found;
			if (suffix_bits == length_bits) {
				// we are done here
				break;
			} else {
				b_word = mem_bitmap_get_next_word(volume_desc);
				continue;
			}
		} else {
			// ok, first high bits not 1
			idx = -1;
			uint64_t rounds[MEM_LOG_WORD_SIZE_IN_BITS * 2];
			uint32_t round_size = MEM_LOG_WORD_SIZE_IN_BITS * 2;
			bits_found = mem_bitmap_find_nbits_in_word(&b_word, rounds, &round_size, length_bits);
			//log_info("Bits found %u length_bits %u start bit %u end bit %u", bits_found, length_bits,
			//	 b_word.start_bit, b_word.end_bit);

			if (bits_found == length_bits) {
				++idx;
				b_words[idx] = b_word;
				break;
			}
			bits_found = mem_bitmap_find_suffix(&b_word, rounds, round_size);
			if (bits_found > 0) {
				++idx;
				b_words[idx] = b_word;
				suffix_bits += bits_found;
			}
			b_word = mem_bitmap_get_next_word(volume_desc);
		}
	}
	// mark the bitmap now, we have surely find something
	for (int i = 0; i <= idx; i++) {
		mem_bitmap_mark_reserved(&b_words[i]);
	}

	base_addr = mem_bitmap_translate_word_to_offt(volume_desc, &b_words[0]);
	free(b_words);
	return base_addr;
}

void mem_bitmap_mark_block_free(struct volume_descriptor *volume_desc, uint64_t dev_offt)
{
	// distance of addr from bitmap end
	uint64_t distance_in_bits = (dev_offt - volume_desc->my_superblock.volume_metadata_size) / SEGMENT_SIZE;
	struct mem_bitmap_word w;
	w.word_id = distance_in_bits / MEM_WORD_SIZE_IN_BITS;
	uint32_t bit_in_word = distance_in_bits % MEM_WORD_SIZE_IN_BITS;

	w.word_addr = &volume_desc->mem_volume_bitmap[w.word_id];
	struct bitmap_byte {
		uint8_t b0 : 1;
		uint8_t b1 : 1;
		uint8_t b2 : 1;
		uint8_t b3 : 1;
		uint8_t b4 : 1;
		uint8_t b5 : 1;
		uint8_t b6 : 1;
		uint8_t b7 : 1;
	};
	struct bitmap_byte *my_word = (struct bitmap_byte *)w.word_addr;
	int m_idx = bit_in_word / 8;
	int m_bit = bit_in_word % 8;
	switch (m_bit) {
	case 0:
		my_word[m_idx].b0 = 1;
		break;
	case 1:
		my_word[m_idx].b1 = 1;
		break;
	case 2:
		my_word[m_idx].b2 = 1;
		break;
	case 3:
		my_word[m_idx].b3 = 1;
		break;
	case 4:
		my_word[m_idx].b4 = 1;
		break;
	case 5:
		my_word[m_idx].b5 = 1;
		break;
	case 6:
		my_word[m_idx].b6 = 1;
		break;
	case 7:
		my_word[m_idx].b7 = 1;
		break;
	}
	return;
}

//<new_persistent_design>
#define MEM_MAX_VOLUME_NAME_SIZE 256
//physics bitch!
#define FINE_STRUCTURE_CONSTANT 72973525664
struct volume_map_entry {
	char volume_name[MEM_MAX_VOLUME_NAME_SIZE];
	struct volume_descriptor *volume_desc;
	uint64_t hash_key;
	UT_hash_handle hh;
};
static struct volume_map_entry *volume_map = NULL;
static pthread_mutex_t volume_map_lock = PTHREAD_MUTEX_INITIALIZER;

static int mem_read_into_buffer(char *buffer, uint32_t start, uint32_t size, off_t dev_offt, int fd)
{
	ssize_t bytes_read = start;
	ssize_t bytes = 0;
	while (bytes_read < size) {
		bytes = pread(fd, &buffer[bytes_read], size - bytes_read, dev_offt + bytes_read);
		if (bytes == -1) {
			log_fatal("Failed to read error code");
			perror("Error");
			assert(0);
			exit(EXIT_FAILURE);
		}
		bytes_read += bytes;
	}
	return 1;
}

/**
 * Prints volume's superblock info
 */
static void mem_print_volume_info(struct superblock *S, char *volume_name)
{
	log_info("<Volume %s info>", volume_name);
	log_info("Volume size in GB: %llu", S->volume_size / (1024 * 1024 * 1024));
	log_info("Able to host up to %u regions useful space in GB: %llu", S->max_regions_num,
		 (S->volume_size - (S->volume_metadata_size + S->unmappedSpace)) / (1024 * 1024 * 1024));
	log_info("Unmapped space %llu", S->unmappedSpace);
	log_info("</Volume %s info>", volume_name);
}

/**
 * Reads from device volume's region superblocks and keeps it in an in memory array
 */
void mem_init_superblock_array(struct volume_descriptor *volume_desc)
{
	volume_desc->pr_regions =
		calloc(1, sizeof(struct pr_superblock_array) +
				  (volume_desc->my_superblock.max_regions_num * sizeof(struct pr_region_superblock)));
	volume_desc->pr_regions->size = volume_desc->my_superblock.max_regions_num;
	off64_t dev_offt = sizeof(struct superblock);
	uint32_t size = volume_desc->my_superblock.max_regions_num * sizeof(struct pr_region_superblock);
	if (!mem_read_into_buffer((char *)volume_desc->pr_regions->region, 0, size, dev_offt, volume_desc->my_fd)) {
		log_fatal("Failed to read volume's region superblocks!");
		exit(EXIT_FAILURE);
	}
	log_info("Restored %s region superblocks in memory", volume_desc->volume_name);
}

/**
 * Recovers from the device all the info about this volume
 */
static volume_descriptor *mem_init_volume(char *volume_name)
{
	struct volume_descriptor *volume_desc;
	if (posix_memalign((void **)&volume_desc, ALIGNMENT_SIZE, sizeof(struct volume_descriptor))) {
		log_fatal("posix memalign failed");
		exit(EXIT_FAILURE);
	}
	memset(volume_desc, 0x00, sizeof(struct volume_descriptor));

	volume_desc->volume_name = calloc(1, strlen(volume_name) + 1);
	memcpy(volume_desc->volume_name, volume_name, strlen(volume_name));

	volume_desc->my_fd = open(volume_name, O_RDWR | O_DIRECT | O_DSYNC);

	if (volume_desc->my_fd < 0) {
		log_fatal("Failed to open %s", volume_name);
		perror("Reason:\n");
		exit(EXIT_FAILURE);
	}
	//read volume superblock (accouning info into memory)
	if (!mem_read_into_buffer((char *)&volume_desc->my_superblock, 0, sizeof(struct superblock), 0,
				  volume_desc->my_fd)) {
		log_fatal("Failed to read volume's %s superblock", volume_name);
		exit(EXIT_FAILURE);
	}
	off64_t device_size = lseek64(volume_desc->my_fd, 0, SEEK_END);
	if (device_size == -1) {
		log_fatal("failed to determine volume size exiting...");
		perror("ioctl");
		exit(EXIT_FAILURE);
	}
	if (device_size != volume_desc->my_superblock.volume_size) {
		log_fatal("Volume sizes do not match! Found %lld expected %lld", device_size,
			  volume_desc->my_superblock.volume_size);
		exit(EXIT_FAILURE);
	}
	if (volume_desc->my_superblock.magic_number != FINE_STRUCTURE_CONSTANT) {
		log_fatal("Volume %s seems not to have been initialized!");
		exit(EXIT_FAILURE);
	}
	volume_desc->mem_volume_bitmap_size = volume_desc->my_superblock.bitmap_size_in_words;
	mem_print_volume_info(&volume_desc->my_superblock, volume_name);
	//Now allocate the in memory bitmap
	volume_desc->mem_volume_bitmap = malloc(volume_desc->mem_volume_bitmap_size * sizeof(uint64_t));
	//set everything to 1 aka free aka don't know
	memset(volume_desc->mem_volume_bitmap, 0xFF, volume_desc->mem_volume_bitmap_size * sizeof(uint64_t));
	mem_init_superblock_array(volume_desc);
	log_info("Recovering ownership registry... XXX TODO XXX");

	volume_desc->curr_word.word_addr = volume_desc->mem_volume_bitmap;
	volume_desc->curr_word.start_bit = 0;
	volume_desc->curr_word.end_bit = 0;
	volume_desc->curr_word.word_id = 0;

	return volume_desc;
}

/**
 * Retrieves or creates if not present the volume_descriptor for a
 * a volume_name
 */
struct volume_descriptor *mem_get_volume_desc(char *volume_name)
{
	pthread_mutex_lock(&volume_map_lock);
	struct volume_map_entry *volume;
	uint64_t hash_key = djb2_hash((unsigned char *)volume_name, strlen(volume_name));

	HASH_FIND_PTR(volume_map, &hash_key, volume);
	if (volume == NULL) {
		log_info("Volume %s not open creating/initializing new volume ...", volume_name);
		volume = calloc(1, sizeof(struct volume_map_entry));
		volume->volume_desc = mem_init_volume(volume_name);
		if (strlen(volume_name) >= MEM_MAX_VOLUME_NAME_SIZE) {
			log_fatal("Volume name too large!");
			exit(EXIT_FAILURE);
		}
		memcpy(volume->volume_name, volume_name, strlen(volume_name));
		volume->hash_key = djb2_hash((unsigned char *)volume_name, strlen(volume_name));
		HASH_ADD_PTR(volume_map, hash_key, volume);
	}
	pthread_mutex_unlock(&volume_map_lock);
	return volume->volume_desc;
}

//http://stackoverflow.com/questions/7666509/hash-function-for-string
unsigned long hash3(unsigned char *str)
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

unsigned long hash_2(unsigned char *str)
{
    unsigned long hash = 0;
    int c;

    while (c = *str++)
	hash +=(int)c;
        //hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

unsigned long hash(unsigned char *name)
{
    unsigned long h = 2166136261;

    while (*name)
    {
        h = (h ^ *name++) * 16777619;
    }

    return (h >> 1); // To avoid negative values when casting to signed integer.
}


#if 0
/* D. J. Bernstein hash function */
static size_t djb_hash(const char* cp)
{
    size_t hash = 5381;
    while (*cp)
        hash = 33 * hash ^ (unsigned char) *cp++;
    return hash;
}

/* Fowler/Noll/Vo (FNV) hash function, variant 1a */
static size_t fnv1a_hash(const char* cp)
{
    size_t hash = 0x811c9dc5;
    while (*cp) {
        hash ^= (unsigned char) *cp++;
        hash *= 0x01000193;
    }
    return hash;
}
#endif

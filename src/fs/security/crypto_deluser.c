#include "cryptfs.h"
#include "deluser.h"

size_t available_key_slots(const struct CryptFS_KeySlot *keys_storage)
{
    size_t i = 0;
    size_t available_slots = 0;
    for (; i < NB_ENCRYPTION_KEYS; i++)
    {
        if (!keys_storage[i].occupied)
            available_slots++;
    }
    return available_slots;
}

size_t occupied_key_slots(const struct CryptFS_KeySlot *keys_storage)
{
    return NB_ENCRYPTION_KEYS - available_key_slots(keys_storage);
}

#include "server.h"
#include <stdlib.h>
#include <string.h>

// GET key
void get_handler(void) {
    char *key;
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    if(!next_string_arg(&arg_state, &key))
        return;

    char *value;
    if(!get_string_by_key(key, &value))
        goto end;

    if(value)
        send_str(value, strlen(value));
    else
        send_nil();
end:
    cmd_restore(&arg_state);
}

// SET key value
void set_handler(void) {
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    char *key = NULL, *value = NULL;
    Object *value_obj = NULL;
    bool should_send_error = true;

    if(!next_string_arg(&arg_state, &key)) {
        should_send_error = false;
        goto error;
    }
    key = strdup(key);
    if(!key)
        goto error;

    if(!next_string_arg(&arg_state, &value)) {
        should_send_error = false;
        goto error;
    }
    value = strdup(value);
    if(!value)
        goto error;

    value_obj = createStringObject(value);
    if(!value_obj)
        goto error;

    if(!hash_table_set(state.keys, key, value_obj))
        goto error;

    cmd_restore(&arg_state);
    send_nil();
    return;

error:
    if(key) free(key);
    if(value) free(value);
    if(value_obj) free(value_obj);
    cmd_restore(&arg_state);
    if(should_send_error)
        send_err(ERR_OUT_OF_MEMORY);
}

// DEL key
void del_handler(void) {
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    char *key;

    if(!next_string_arg(&arg_state, &key))
        return;
    HashTableNode *value_node = hash_table_get(state.keys, key);
    uint32_t result;
    if(value_node) {
        hash_table_remove(state.keys, value_node);
        result = 1;
    } else {
        result = 0;
    }
    cmd_restore(&arg_state);
    send_uint(result);
}

// KEYS
void keys_handler(void) {
    if(!send_arr())
        return;

    for(HashTableIterator it = hash_table_begin(state.keys);
        hash_table_has_next(&it);
        hash_table_next(&it))
    {
        if(!send_str(it.node->key, strlen(it.node->key)))
            return;
    }

    end_arr(state.keys->size);
}

// golden
// 6/12/2018
//

#include <ksdk.h>
#include "hooks.h"

int _main(void) {
    init_ksdk();

    printf("[ps4debug] kernel base 0x%llX\n", get_kbase());

    if(install_hooks()) {
        printf("[ps4debug] failed to install hooks\n");
        return 1;
    }

    return 0;
}

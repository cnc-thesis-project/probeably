#ifndef _PROBABLY_DEBUG_H
#define _PROBABLY_DEBUG_H

#define PRB_DEBUG(MOD, MSG)
#ifdef PRB_DEBUG_ENABLED
printf("[%s] %s\n", MOD, MSG)
#else

#endif

#endif

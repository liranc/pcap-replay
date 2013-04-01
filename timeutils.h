
#ifndef __TIMEUTILS__
#define __TIMEUTILS__

#include <time.h>
#include "pcaptypes.h"

struct timeval timeval_subtract (struct timeval *x, struct timeval *y);
struct timeval wait_until_next(struct timeval *last_capture, struct pcaprec_hdr_s *next);

#endif

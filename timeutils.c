#include "timeutils.h"

#include <unistd.h>

struct timeval timeval_subtract (struct timeval *x, struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (int)((y->tv_usec - x->tv_usec) / 1000000 + 1);
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (int)((x->tv_usec - y->tv_usec) / 1000000);
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
        tv_usec is certainly positive. */
	struct timeval result;
	result.tv_sec = x->tv_sec - y->tv_sec;
	result.tv_usec = x->tv_usec - y->tv_usec;

	return result;
}

struct timeval wait_until_next(struct timeval *last, struct pcaprec_hdr_s *next){

	struct timeval next_time;
	next_time.tv_sec = next->ts_sec;
	next_time.tv_usec = next->ts_usec;

	if(last->tv_sec != -1){

		struct timeval diff = timeval_subtract(&next_time, last);

		useconds_t time_in_micros = (useconds_t)(1000000 * diff.tv_sec + diff.tv_usec);
		usleep(time_in_micros);
	}

	return next_time;
}

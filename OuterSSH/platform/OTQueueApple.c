#if defined(__APPLE__)
#include "OTQueue.h"

#include <stdlib.h>

void *objc_autoreleasePoolPush(void);
void objc_autoreleasePoolPop(void *pool);

typedef struct {
    void *context;
    void (*function)(void *);
} BackgroundWork;

/* Each job gets an autorelease pool, since its callbacks may use Objective-C. */
static void run_background_work(void *pointer)
{
    BackgroundWork work = *(BackgroundWork *)pointer;
    free(pointer);
    void *pool = objc_autoreleasePoolPush();
    work.function(work.context);
    objc_autoreleasePoolPop(pool);
}

void otqueue_async_background(void *context, void (*function)(void *))
{
    BackgroundWork *work = malloc(sizeof(*work));
    if (work == NULL) abort();
    *work = (BackgroundWork){context, function};
    dispatch_async_f(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), work, run_background_work);
}

#endif

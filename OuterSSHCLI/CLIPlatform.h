#ifndef OUTERSSH_CLI_PLATFORM_H
#define OUTERSSH_CLI_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <OuterSSH/OuterSSH.h>

void *cli_allocate(size_t size);
char *cli_copy(const char *text);
void cli_free_allocations(void);
char *cli_home(void);
char *cli_username(void);
char *cli_expand_home(const char *path);
char *cli_resolve_configuration(char *const arguments[]);
bool cli_prompt(const char *prompt, char *buffer, size_t capacity, bool echo);
bool cli_append_known_host(const char *path, const char *line, size_t length);
bool cli_disable_agent(void);
void *cli_semaphore_create(void);
void cli_semaphore_signal(void *semaphore);
void cli_semaphore_wait(void *semaphore);
void cli_semaphore_destroy(void *semaphore);

typedef struct CLIEvents CLIEvents;
/* Creates an event queue. events_posted runs serially on a background thread or
 * queue while the event queue has pending events. */
CLIEvents *cli_events_start(void (*events_posted)(void *), void *user);
OuterSSHEventQueue *cli_event_queue(CLIEvents *events);
/* Call after every pool and frontend has been destroyed. Returns after any
 * events_posted call in progress has finished, then destroys the event queue. */
void cli_events_stop(CLIEvents *events);
bool cli_prepare_signals(void);
void cli_wait_for_signal(void);

#endif

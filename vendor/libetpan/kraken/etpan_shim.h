#include <libetpan/mailimap.h>

/* What the server reported when the mailbox was selected. libetpan's selection info has
   bitfields, which Zig's C translation cannot read, so this copies out what Kraken needs.
   Returns 0 when no mailbox is selected. */
int kraken_imap_selection(mailimap *session, uint32_t *exists, uint32_t *recent, uint32_t *uidnext,
    uint32_t *uidvalidity, uint32_t *first_unseen, clist **flags);

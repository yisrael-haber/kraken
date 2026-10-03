#include <stddef.h>
#include "etpan_shim.h"

int kraken_imap_selection(mailimap *session, uint32_t *exists, uint32_t *recent, uint32_t *uidnext,
    uint32_t *uidvalidity, uint32_t *first_unseen, clist **flags)
{
  struct mailimap_selection_info *info = session->imap_selection_info;

  if (info == NULL)
    return 0;
  *exists = info->sel_exists;
  *recent = info->sel_recent;
  *uidnext = info->sel_uidnext;
  *uidvalidity = info->sel_uidvalidity;
  *first_unseen = info->sel_first_unseen;
  *flags = info->sel_flags == NULL ? NULL : info->sel_flags->fl_list;
  return 1;
}

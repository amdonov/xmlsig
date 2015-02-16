#include "xmlsig.h"

void
init ()
{
  xmlInitParser ();
  LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
  xmlSubstituteEntitiesDefault (1);
}

int
canonicalize (xmlDocPtr doc, xmlChar ** result)
{
  return xmlC14NDocDumpMemory (doc, NULL, XML_C14N_1_0, NULL, 0, result);
}

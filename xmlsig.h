#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/c14n.h>

void init ();
int canonicalize (xmlDocPtr doc, xmlChar ** result);

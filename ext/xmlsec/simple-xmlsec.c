#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ruby.h>
 
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
 
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/crypto.h>
#include <xmlsec/bn.h>

 
int initialize() ;
void SecShutdown() ;
void cleanup(xmlSecDSigCtxPtr dsigCtx) ;
void xmlSecErrorCallback(const char* file, int line, const char* func, const char* errorObject, const char* errorSubject, int reason, const char* msg); 
static int  
xmlSecAppAddIDAttr(xmlNodePtr node, const xmlChar* attrName, const xmlChar* nodeName, const xmlChar* nsHref) {
    xmlAttrPtr attr, tmpAttr;
    xmlNodePtr cur;
    xmlChar* id;
    
    if((node == NULL) || (attrName == NULL) || (nodeName == NULL)) {
        return(-1);
    }
    
    /* process children first because it does not matter much but does simplify code */
    cur = xmlSecGetNextElementNode(node->children);
    while(cur != NULL) {
        if(xmlSecAppAddIDAttr(cur, attrName, nodeName, nsHref) < 0) {
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* node name must match */
    if(!xmlStrEqual(node->name, nodeName)) {
        return(0);
    }
        
    /* if nsHref is set then it also should match */    
    if((nsHref != NULL) && (node->ns != NULL) && (!xmlStrEqual(nsHref, node->ns->href))) {
        return(0);
    }
    
    /* the attribute with name equal to attrName should exist */
    for(attr = node->properties; attr != NULL; attr = attr->next) {
        if(xmlStrEqual(attr->name, attrName)) {
            break;
        }
    }
    if(attr == NULL) {
        return(0);
    }
    
    /* and this attr should have a value */
    id = xmlNodeListGetString(node->doc, attr->children, 1);
    if(id == NULL) {
        return(0);
    }
    
    /* check that we don't have same ID already */
    tmpAttr = xmlGetID(node->doc, id);
    if(tmpAttr == NULL) {
        xmlAddID(NULL, node->doc, id, attr);
    } else if(tmpAttr != attr) {
        fprintf(stderr, "Error: duplicate ID attribute \"%s\"\n", id);  
        xmlFree(id);
        return(-1);
    }
    xmlFree(id);
    return(0);
}
 
/* functions */
int verify_file(const char* xmlMessage, const char* key) {
  xmlDocPtr doc = NULL;
  xmlNodePtr node = NULL;
  xmlSecDSigCtxPtr dsigCtx = NULL;
  int res = 0;
  initialize();
 
  doc = xmlParseDoc((xmlChar *) xmlMessage) ;
 
  if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
	cleanup(dsigCtx);
	rb_raise(rb_eRuntimeError, "unable to parse XML document");
  }
    
  /* find start node */
  node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
  if(node == NULL) {
	cleanup(dsigCtx);
	rb_raise(rb_eRuntimeError, "could not find start node in XML document");
  }

  xmlNodePtr cur = xmlSecGetNextElementNode(doc->children);
  while(cur != NULL) {
	  if(xmlSecAppAddIDAttr(cur, "ID", "Response", "urn:oasis:names:tc:SAML:2.0:protocol") < 0) {
		  cleanup(dsigCtx);
		  rb_raise(rb_eRuntimeError, "could not define ID attribute");
	  }
	  cur = xmlSecGetNextElementNode(cur->next);
  }

  /* create signature context */
  dsigCtx = xmlSecDSigCtxCreate(NULL);
  if(dsigCtx == NULL) {
	cleanup(dsigCtx);
	rb_raise(rb_eRuntimeError, "could not create signature context");
  }
 
	/* load public key */
	dsigCtx->signKey = xmlSecCryptoAppKeyLoadMemory(key, strlen(key), xmlSecKeyDataFormatCertPem, NULL, NULL, NULL);
	if(dsigCtx->signKey == NULL) {
		cleanup(dsigCtx);
		rb_raise(rb_eRuntimeError, "could not read public pem key %s", key);
	}
	 
  /* Verify signature */
  if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
	cleanup(dsigCtx);
	rb_raise(rb_eRuntimeError, "Document does not seem to be in an XMLDsig format");
  }
        
  /* print verification result to stdout */
  if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
	  res = 1;
  } else {
	  res = 0;
  }    
  cleanup(dsigCtx);
  return res;
}

void cleanup(xmlSecDSigCtxPtr dsigCtx) {
  if(dsigCtx != NULL) {
    xmlSecDSigCtxDestroy(dsigCtx);
  }
  SecShutdown() ;
}
 
int initialize()
{
  /* Init libxml and libxslt libraries */
  xmlInitParser();
  LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
  xmlSubstituteEntitiesDefault(1);
            
  /* Init xmlsec library */
  if(xmlSecInit() < 0) {
    fprintf(stdout, "Error: xmlsec initialization failed.\n");
    fflush(stdout) ;
    return(-1);
  }
 
  /* Check loaded library version */
  if(xmlSecCheckVersion() != 1) {
    fprintf(stderr, "Error: loaded xmlsec library version is not compatible.\n");
    return(-1);
  }
 
  /* Load default crypto engine if we are supporting dynamic
   * loading for xmlsec-crypto libraries. Use the crypto library
   * name ("openssl", "nss", etc.) to load corresponding
   * xmlsec-crypto library.
   */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
  if(xmlSecCryptoDLLoadLibrary(BAD_CAST XMLSEC_CRYPTO) < 0) {
    fprintf(stdout, "Error: unable to load default xmlsec-crypto library. Make sure\n"
            "that you have it installed and check shared libraries path\n"
            "(LD_LIBRARY_PATH) envornment variable.\n");
    fflush(stdout) ;
    return(-1);    
  }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */
 
  /* Init crypto library */
  if(xmlSecCryptoAppInit(NULL) < 0) {
    fprintf(stderr, "Error: crypto initialization failed.\n");
    return(-1);
  }
 
  /* Init xmlsec-crypto library */
  if(xmlSecCryptoInit() < 0) {
    fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
    return(-1);
  }
  xmlSecErrorsSetCallback(xmlSecErrorCallback);
}

void xmlSecErrorCallback(const char* file, int line, const char* func, const char* errorObject, const char* errorSubject, int reason, const char* msg) {
	rb_raise(rb_eRuntimeError, "XMLSec error in %s: %s", func, msg);
}
 
void SecShutdown()
{
  /* Shutdown xmlsec-crypto library */
  xmlSecCryptoShutdown();
  
  /* Shutdown crypto library */
  xmlSecCryptoAppShutdown();
  
  /* Shutdown xmlsec library */
  xmlSecShutdown();
  
  /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
  xsltCleanupGlobals();            
#endif /* XMLSEC_NO_XSLT */
  xmlCleanupParser();
  return ;
}

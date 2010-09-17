#include <stdlib.h>
#include <string.h>
#include <assert.h>
 
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
    
  assert(xmlMessage);
  assert(key);
 
  doc = xmlParseDoc((xmlChar *) xmlMessage) ;
 
  if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
    fprintf(stderr, "Error: unable to parse file \"%s\"\n", xmlMessage);
    goto done;    
  }
    
  /* find start node */
  node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
  if(node == NULL) {
    fprintf(stdout, "Error: start node not found in \"%s\"\n", xmlMessage);
    goto done;    
  }

  xmlNodePtr cur = xmlSecGetNextElementNode(doc->children);
  while(cur != NULL) {
	  if(xmlSecAppAddIDAttr(cur, "ID", "Response", "urn:oasis:names:tc:SAML:2.0:protocol") < 0) {
		  fprintf(stderr, "Error: failed to add ID attribute");
goto done;
	  }
	  cur = xmlSecGetNextElementNode(cur->next);
  }

  /* create signature context */
  dsigCtx = xmlSecDSigCtxCreate(NULL);
  if(dsigCtx == NULL) {
    fprintf(stdout,"Error: failed to create signature context\n");
    goto done;
  }
 
	/* load public key */
	dsigCtx->signKey = xmlSecCryptoAppKeyLoadMemory(key, strlen(key), xmlSecKeyDataFormatCertPem, NULL, NULL, NULL);
	if(dsigCtx->signKey == NULL) {
		fprintf(stdout,"Error: failed to load public pem key from \"%s\"\n", key);
		goto done;
	}
 
  /* set key name to the file name, this is just an example! */
  if(xmlSecKeySetName(dsigCtx->signKey, key) < 0) {
    fprintf(stdout,"Error: failed to set key name for key from \"%s\"\n", key);
    goto done;
  }
	 
  /* Verify signature */
  if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
    fprintf(stdout,"Error: signature verify\n");
    goto done;
  }
        
  /* print verification result to stdout */
  if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
    fprintf(stdout, "Signature is OK\n");
  } else {
    fprintf(stdout, "Signature is INVALID\n");
  }    
 
  /* success */
  res = 1;
 
 done:    
  /* cleanup */
  if(dsigCtx != NULL) {
    xmlSecDSigCtxDestroy(dsigCtx);
  }
    
  SecShutdown() ;
 
  return(res);
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

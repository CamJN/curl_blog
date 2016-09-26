#include <curl/curl.h>
#include <string>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

using namespace std;

const char* cert_label = "Name of the certificate as it appears in keychain access";
const char* domain = "https://example.dev/v1/check.json";
const char* ca_path = "/path/to/ca.crt";
const char* cert_path = "/path/to/client_cert.p12";
const char* cert_pw = "1234";

static OSStatus LookupKeychainItem(const char *label,
                                   SecIdentityRef *out_cert_and_key)
{
  OSStatus status = errSecItemNotFound;

  if(kSecClassIdentity != NULL) {
    CFTypeRef keys[4];
    CFTypeRef values[4];
    CFDictionaryRef query_dict;
    CFStringRef label_cf = CFStringCreateWithCString(NULL, label,
                                                     kCFStringEncodingUTF8);

    /* Set up our search criteria and expected results: */
    values[0] = kSecClassIdentity; /* we want a certificate and a key */
    keys[0] = kSecClass;
    values[1] = kCFBooleanFalse;    /* we don't need a reference */
    keys[1] = kSecReturnRef;
    values[2] = kSecMatchLimitOne; /* one is enough, thanks */
    keys[2] = kSecMatchLimit;
    /* identity searches need a SecPolicyRef in order to work */
    values[3] = SecPolicyCreateSSL(false, label_cf);
    keys[3] = kSecMatchPolicy;
    query_dict = CFDictionaryCreate(NULL, (const void **)keys,
                                    (const void **)values, 4L,
                                    &kCFCopyStringDictionaryKeyCallBacks,
                                    &kCFTypeDictionaryValueCallBacks);
    CFRelease(values[3]);
    CFRelease(label_cf);

    /* Do we have a match? */
    status = SecItemCopyMatching(query_dict, (CFTypeRef *)out_cert_and_key);
    CFRelease(query_dict);
  }

  return status;
}

SecAccessRef createAccess()
{
  SecAccessRef access=NULL;
  if (SecAccessCreate(CFStringCreateWithCString(NULL, cert_label, kCFStringEncodingUTF8), NULL, &access)){
    printf("SecAccessCreate failed\n");
    return NULL;
  }
  return access;
}

static OSStatus CopyIdentityFromPKCS12File(const char *cPath,
                                           const char *cPassword,
                                           SecIdentityRef *out_cert_and_key)
{
  OSStatus status = errSecItemNotFound;
  CFURLRef pkcs_url = CFURLCreateFromFileSystemRepresentation(NULL,
                                                              (const UInt8 *)cPath, strlen(cPath), false);
  CFStringRef password = cPassword ? CFStringCreateWithCString(NULL,
                                                               cPassword, kCFStringEncodingUTF8) : NULL;
  CFDataRef pkcs_data = NULL;

  if(CFURLCreateDataAndPropertiesFromResource(NULL, pkcs_url, &pkcs_data,
                                              NULL, NULL, &status)) {
    SecAccessRef access = createAccess();
    const void *cKeys[] = {kSecImportExportPassphrase,kSecImportExportAccess};
    //kSecTrustSettingsKeyUseAny
    const void *cValues[] = {password,access};
    CFDictionaryRef options = CFDictionaryCreate(NULL, cKeys, cValues,
                                                 2L, NULL, NULL);
    CFArrayRef items = NULL;

    /* Here we go: */
    status = SecPKCS12Import(pkcs_data, options, &items);

    if(items)
      CFRelease(items);
    CFRelease(options);
    CFRelease(pkcs_data);
  }

  if(password)
    CFRelease(password);
  CFRelease(pkcs_url);
  return status;
}

static size_t receiveResponseBytes(void *buffer, size_t size, size_t nmemb, void *userData) {
  string *responseData = (string *) userData;
  responseData->append((const char *) buffer, size * nmemb);
  return size * nmemb;
}

void prepareCurlPOST(CURL *curl, string &bodyJsonString, string *responseData, struct curl_slist **chunk) {
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_URL, domain);
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 0);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, bodyJsonString.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, bodyJsonString.length());
  *chunk = curl_slist_append(NULL, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *chunk);
  curl_easy_setopt(curl, CURLOPT_SSLCERT, cert_label);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receiveResponseBytes);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, responseData);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 180);
  curl_easy_setopt(curl, CURLOPT_CAINFO, ca_path);
}

void preAuthKey(){
  SecIdentityRef id = NULL;
  if(LookupKeychainItem(cert_label,&id) == errSecItemNotFound){
    OSStatus status = SecKeychainSetUserInteractionAllowed(false);
    if(status != errSecSuccess){
      printf("%s\n",CFStringGetCStringPtr(SecCopyErrorMessageString(status,NULL),kCFStringEncodingUTF8));
    }
    CopyIdentityFromPKCS12File(cert_path,cert_pw,&id);
    status = SecKeychainSetUserInteractionAllowed(true);
    if(status != errSecSuccess){
      printf("%s\n",CFStringGetCStringPtr(SecCopyErrorMessageString(status,NULL),kCFStringEncodingUTF8));
    }
  }
}

int main(){
  preAuthKey();
  CURL* curl = curl_easy_init();
  struct curl_slist *chunk = NULL;
  string responseData;
  long responseCode;
  string bodyJsonString = "{\"version\": 1}";
  prepareCurlPOST(curl, bodyJsonString, &responseData, &chunk);
  fprintf(stderr,"%s\n",curl_easy_strerror(curl_easy_perform(curl)));
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
  if (responseCode != 200) {
    fprintf(stderr, "HTTP %d %s\n", (int) responseCode, responseData.c_str());
  }
  curl_slist_free_all(chunk);
  curl_easy_cleanup(curl);
}

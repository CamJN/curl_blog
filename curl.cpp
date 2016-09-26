#include <curl/curl.h>
#include <string>

using namespace std;

const char* domain = "https://example.dev/v1/check.json";
const char* ca_path = "/path/to/ca.crt";
const char* cert_path = "/path/to/client_cert.p12";
const char* cert_pw = "1234";

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
  curl_easy_setopt(curl, CURLOPT_SSLCERT, cert_path);
  curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "P12");
  curl_easy_setopt(curl, CURLOPT_SSLCERTPASSWD, cert_pw);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receiveResponseBytes);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, responseData);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 180);
  curl_easy_setopt(curl, CURLOPT_CAINFO, ca_path);
}

int main(){
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

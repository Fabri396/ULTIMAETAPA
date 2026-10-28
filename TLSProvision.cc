#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <openssl/crypto.h>

static void require(bool ok,const std::string& msg){if(!ok)throw std::runtime_error(msg);}
static void extension(X509* cert,X509* issuer,int nid,const std::string& val){
 X509V3_CTX ctx; X509V3_set_ctx(&ctx,issuer,cert,nullptr,nullptr,0);
 X509_EXTENSION* ext=X509V3_EXT_conf_nid(nullptr,&ctx,nid,const_cast<char*>(val.c_str()));
 require(ext!=nullptr,"extension X509 invalida");require(X509_add_ext(cert,ext,-1)==1,"X509_add_ext");X509_EXTENSION_free(ext);
}
static EVP_PKEY* newKey(){
 EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,nullptr);require(ctx!=nullptr,"key context");
 require(EVP_PKEY_keygen_init(ctx)>0,"keygen init");require(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,3072)>0,"rsa bits");
 EVP_PKEY* key=nullptr;require(EVP_PKEY_keygen(ctx,&key)>0,"keygen");EVP_PKEY_CTX_free(ctx);return key;
}
static X509* newCert(EVP_PKEY* key,const std::string& cn,X509* issuer,EVP_PKEY* signer,const std::string& san){
 X509* cert=X509_new();require(cert!=nullptr,"X509_new");
 require(X509_set_version(cert,2)==1,"version");unsigned char serial[16];require(RAND_bytes(serial,sizeof(serial))==1,"random");
 BIGNUM* bn=BN_bin2bn(serial,sizeof(serial),nullptr);ASN1_INTEGER* ai=BN_to_ASN1_INTEGER(bn,nullptr);require(ai!=nullptr,"serial");
 require(X509_set_serialNumber(cert,ai)==1,"serial set");ASN1_INTEGER_free(ai);BN_free(bn);
 X509_gmtime_adj(X509_getm_notBefore(cert),-60);X509_gmtime_adj(X509_getm_notAfter(cert),365L*24*3600);
 require(X509_set_pubkey(cert,key)==1,"pubkey");X509_NAME* name=X509_get_subject_name(cert);
 require(X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char*)cn.c_str(),-1,-1,0)==1,"CN");
 require(X509_set_issuer_name(cert,issuer?X509_get_subject_name(issuer):name)==1,"issuer");
 if(!issuer){extension(cert,cert,NID_basic_constraints,"critical,CA:FALSE");extension(cert,cert,NID_key_usage,"critical,digitalSignature,keyEncipherment");extension(cert,cert,NID_ext_key_usage,"serverAuth,clientAuth");extension(cert,cert,NID_subject_alt_name,san);}
 else {extension(cert,issuer,NID_basic_constraints,"critical,CA:FALSE");extension(cert,issuer,NID_key_usage,"critical,digitalSignature,keyEncipherment");extension(cert,issuer,NID_ext_key_usage,"serverAuth");extension(cert,issuer,NID_subject_alt_name,san);}
 require(X509_sign(cert,signer,EVP_sha256())>0,"sign");return cert;
}
static void writeKey(const std::string& file,EVP_PKEY* key){FILE* f=fopen(file.c_str(),"w");require(f!=nullptr,"abrir key");chmod(file.c_str(),0600);bool ok=PEM_write_PrivateKey(f,key,nullptr,nullptr,0,nullptr,nullptr)==1;fclose(f);require(ok,"write key");}
static void writeCert(const std::string& file,X509* cert){FILE* f=fopen(file.c_str(),"w");require(f!=nullptr,"abrir crt");bool ok=PEM_write_X509(f,cert)==1;fclose(f);require(ok,"write crt");}
static void ensureDir(const std::string& path) {
 std::string partial;
 for(size_t i=0;i<path.size();++i){partial+=path[i];
  if(path[i]=='/' && partial.size()>1 && mkdir(partial.c_str(),0700)!=0 && errno!=EEXIST)
   throw std::runtime_error("mkdir "+partial+": "+strerror(errno));
 }
 if(mkdir(path.c_str(),0700)!=0 && errno!=EEXIST)
  throw std::runtime_error("mkdir "+path+": "+strerror(errno));
}
static bool exists(const std::string& p){struct stat st;return stat(p.c_str(),&st)==0;}
// Configuracion simplificada: una identidad TLS compartida para la red de laboratorio.
static bool validExisting(const std::vector<std::string>& hosts) {
 const std::string d="certs/";
 if(!exists(d+"server.key") || !exists(d+"server.crt") || !exists(d+"siqp-trust.crt")) return false;
 FILE* f=fopen((d+"server.crt").c_str(),"r");if(!f)return false;
 X509* cert=PEM_read_X509(f,nullptr,nullptr,nullptr);fclose(f);if(!cert)return false;
 f=fopen((d+"server.key").c_str(),"r");if(!f){X509_free(cert);return false;}
 EVP_PKEY* key=PEM_read_PrivateKey(f,nullptr,nullptr,nullptr);fclose(f);
 bool ok=key && X509_check_private_key(cert,key)==1 &&
   X509_check_purpose(cert,X509_PURPOSE_SSL_SERVER,0)==1 &&
   X509_cmp_current_time(X509_get0_notBefore(cert))<=0 &&
   X509_cmp_current_time(X509_get0_notAfter(cert))>0 &&
   X509_check_ip_asc(cert,"127.0.0.1",0)==1;
 for(const auto& h:hosts){if(h.empty())continue;
   bool ip=h.find_first_not_of("0123456789.")==std::string::npos;
   if((ip?X509_check_ip_asc(cert,h.c_str(),0):X509_check_host(cert,h.c_str(),h.size(),0,nullptr))!=1)ok=false;
 }
 f=fopen((d+"siqp-trust.crt").c_str(),"r");
 X509* trust=f?PEM_read_X509(f,nullptr,nullptr,nullptr):nullptr;if(f)fclose(f);
 if(!trust || X509_cmp(cert,trust)!=0)ok=false;
 X509_free(trust);EVP_PKEY_free(key);X509_free(cert);return ok;
}
static void initShared(const std::vector<std::string>& hosts) {
 const std::string dir="certs";ensureDir(dir);
 if(validExisting(hosts)) {std::cout<<"TLS ya configurado y verificado; se conserva.\n";return;}
 const bool any=exists(dir+"/server.key") || exists(dir+"/server.crt") || exists(dir+"/siqp-trust.crt");
 if(any){
  // Conservar los archivos originales antes de reparar una configuracion invalida.
  const std::string backup="certs-backup-"+std::to_string(static_cast<long long>(time(nullptr)));
  ensureDir(backup);
  for(const auto& name:{"server.key","server.crt","siqp-trust.crt"}){
   const std::string src=dir+"/"+name;
   if(exists(src))require(rename(src.c_str(),(backup+"/"+name).c_str())==0,"respaldar "+src);
  }
  std::cout<<"Configuracion anterior respaldada en "<<backup<<"\n";
 }
 std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(newKey(),EVP_PKEY_free);
 std::string san="IP:127.0.0.1,DNS:localhost";
 for(const auto& h:hosts){if(h.empty())continue;
  bool ip=h.find_first_not_of("0123456789.")==std::string::npos;
  san+=","+std::string(ip?"IP:":"DNS:")+h;
 }
 std::unique_ptr<X509,decltype(&X509_free)> cert(newCert(key.get(),"TicAmazon-Lab",nullptr,key.get(),san),X509_free);
 writeKey(dir+"/server.key",key.get());writeCert(dir+"/server.crt",cert.get());writeCert(dir+"/siqp-trust.crt",cert.get());
 require(validExisting(hosts),"El certificado generado no paso la validacion");
 std::cout<<"TLS generado y verificado en certs/.\n";
}

int main(int argc,char** argv) {
 try {
  if(argc<2 || std::string(argv[1])!="init") {
   std::cerr << "Uso: ./TLSProvision.out init [IP_o_DNS_1 IP_o_DNS_2 ...]\n";
   return 1;
  }
  std::vector<std::string> hosts;
  for(int i=2;i<argc;i++) hosts.push_back(argv[i]);
  initShared(hosts);
  return 0;
 } catch(const std::exception& e) {std::cerr << "TLSProvision: " << e.what() << "\n";return 1;}
}

/* Native OpenSSL QUIC authentication probe. Public APIs only.
 * role port chain.pem key.pem root.pem group extension_bytes log_prefix
 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
static FILE *msglog, *keylog;
static double stamp(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
static void tls_message(int wp,int version,int type,const void *buf,size_t len,SSL *ssl,void *arg){
 (void)version;(void)ssl;(void)arg;
 if(type!=SSL3_RT_HANDSHAKE||!len)return;
 const unsigned char *b=buf;
 fprintf(msglog,"{\"t\":%.9f,\"write\":%d,\"type\":%u,\"length\":%zu,\"hex\":\"",stamp(),wp,b[0],len);
 char *hex=malloc(2*len);static const char hd[]="0123456789abcdef";
 if(hex){for(size_t i=0;i<len;i++){hex[2*i]=hd[b[i]>>4];hex[2*i+1]=hd[b[i]&15];}fwrite(hex,1,2*len,msglog);free(hex);}
 fprintf(msglog,"\"}\n");fflush(msglog);
}
static void key_line(const SSL *ssl,const char *line){(void)ssl;fprintf(keylog,"%s\n",line);fflush(keylog);}
static const unsigned char alpn[]={8,'o','s','s','l','t','e','s','t'};
static int choose_alpn(SSL *ssl,const unsigned char **out,unsigned char *olen,const unsigned char *in,unsigned int ilen,void *arg){
 (void)ssl;(void)arg;
 return SSL_select_next_proto((unsigned char**)out,olen,alpn,sizeof(alpn),in,ilen)==OPENSSL_NPN_NEGOTIATED?SSL_TLSEXT_ERR_OK:SSL_TLSEXT_ERR_ALERT_FATAL;
}
static unsigned char extension[16000];static size_t extlen;
static int add_extension(SSL *s,unsigned int typ,unsigned int ctx,const unsigned char **out,size_t *n,X509 *x,size_t chainidx,int *alert,void *arg){
 (void)s;(void)typ;(void)ctx;(void)x;(void)chainidx;(void)alert;(void)arg;
 *out=extension;*n=extlen;return 1;
}
int main(int argc,char **argv){
 if(argc!=9){fprintf(stderr,"role port chain key root group extension_bytes log_prefix\n");return 2;}
 const int server=!strcmp(argv[1],"server");int ret=1,fd=-1;SSL_CTX *ctx=NULL;SSL *s=NULL,*listener=NULL;BIO_ADDR *peer=NULL;
 char path[4096];snprintf(path,sizeof(path),"%s.tls.jsonl",argv[8]);msglog=fopen(path,"w");snprintf(path,sizeof(path),"%s.keys",argv[8]);keylog=fopen(path,"w");
 if(!msglog||!keylog)goto done;
 ctx=SSL_CTX_new(server?OSSL_QUIC_server_method():OSSL_QUIC_client_method());if(!ctx)goto done;
 SSL_CTX_set_msg_callback(ctx,tls_message);SSL_CTX_set_keylog_callback(ctx,key_line);
 if(!SSL_CTX_set1_groups_list(ctx,argv[6]))goto done;
 if(!SSL_CTX_set_ciphersuites(ctx,"TLS_AES_128_GCM_SHA256"))goto done;
 if(getenv("QUIC_COMPRESS") && !strcmp(getenv("QUIC_COMPRESS"),"1")){
  int alg=1;if(!SSL_CTX_set1_cert_comp_preference(ctx,&alg,1))goto done;
 }else SSL_CTX_set_options(ctx,SSL_OP_NO_TX_CERTIFICATE_COMPRESSION|SSL_OP_NO_RX_CERTIFICATE_COMPRESSION);
 SSL_CTX_set_num_tickets(ctx,0);SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_OFF);
 struct sockaddr_in sa={0};sa.sin_family=AF_INET;sa.sin_port=htons(atoi(argv[2]));sa.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 fd=socket(AF_INET,SOCK_DGRAM,0);if(fd<0)goto done;
 if(server){
  if(!SSL_CTX_use_certificate_chain_file(ctx,argv[3])||!SSL_CTX_use_PrivateKey_file(ctx,argv[4],SSL_FILETYPE_PEM)||!SSL_CTX_check_private_key(ctx))goto done;
  if(getenv("QUIC_COMPRESS") && !strcmp(getenv("QUIC_COMPRESS"),"1")){
   SSL_CTX *cc=SSL_CTX_new(TLS_server_method());unsigned char *buf=NULL;size_t orig=0,n=0;
   if(!cc||!SSL_CTX_use_certificate_chain_file(cc,argv[3])||!SSL_CTX_use_PrivateKey_file(cc,argv[4],SSL_FILETYPE_PEM)){SSL_CTX_free(cc);goto done;}
   n=SSL_CTX_get1_compressed_cert(cc,1,&buf,&orig);
   int ok=n && SSL_CTX_set1_compressed_cert(ctx,1,buf,n,orig);if(!ok)fprintf(stderr,"compression n=%zu orig=%zu ok=%d\n",n,orig,ok);OPENSSL_free(buf);SSL_CTX_free(cc);if(!ok)goto done;
  }
  SSL_CTX_set_alpn_select_cb(ctx,choose_alpn,NULL);
  if(bind(fd,(struct sockaddr*)&sa,sizeof(sa)))goto done;
  listener=SSL_new_listener(ctx,getenv("QUIC_RETRY") && !strcmp(getenv("QUIC_RETRY"),"1") ? 0 : SSL_LISTENER_FLAG_NO_VALIDATE);if(!listener||!SSL_set_fd(listener,fd)||!SSL_listen(listener))goto done;
  printf("{\"event\":\"ready\",\"t\":%.9f}\n",stamp());fflush(stdout);
  s=SSL_accept_connection(listener,0);if(!s)goto done;
  if(SSL_accept(s)!=1)goto done;
 }else{
  if(!SSL_CTX_load_verify_locations(ctx,argv[5],NULL))goto done;
  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
  extlen=strtoul(argv[7],NULL,10);if(extlen>sizeof(extension))goto done;
  if(extlen&&!SSL_CTX_add_custom_ext(ctx,0xffa5,SSL_EXT_CLIENT_HELLO,add_extension,NULL,NULL,NULL,NULL))goto done;
  if(connect(fd,(struct sockaddr*)&sa,sizeof(sa)))goto done;
  s=SSL_new(ctx);if(!s||!SSL_set_fd(s,fd))goto done;
  peer=BIO_ADDR_new();if(!peer||!BIO_ADDR_rawmake(peer,AF_INET,&sa.sin_addr,sizeof(sa.sin_addr),sa.sin_port)||!SSL_set1_initial_peer_addr(s,peer))goto done;
  if(!SSL_set_tlsext_host_name(s,"localhost")||!SSL_set1_host(s,"localhost")||SSL_set_alpn_protos(s,alpn,sizeof(alpn)))goto done;
  printf("{\"event\":\"start\",\"t\":%.9f}\n",stamp());fflush(stdout);
  if(SSL_connect(s)!=1)goto done;
  if(SSL_get_verify_result(s)!=X509_V_OK)goto done;
 }
 printf("{\"event\":\"complete\",\"t\":%.9f,\"group\":\"%s\",\"verify_result\":%ld,\"resumed\":%d,\"cipher\":\"%s\"}\n",stamp(),SSL_group_to_name(s,SSL_get_negotiated_group(s)),SSL_get_verify_result(s),SSL_session_reused(s),SSL_get_cipher_name(s));fflush(stdout);
 if(!server){double end=stamp()+.5;while(stamp()<end){SSL_handle_events(s);struct timespec pause={0,1000000};nanosleep(&pause,NULL);}}
 ret=0;
 done:
 if(ret)ERR_print_errors_fp(stderr);
 SSL_free(s);SSL_free(listener);SSL_CTX_free(ctx);BIO_ADDR_free(peer);if(fd>=0)close(fd);if(msglog)fclose(msglog);if(keylog)fclose(keylog);return ret;
}

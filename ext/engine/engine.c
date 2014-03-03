//Modified from: https://github.com/puma/puma/blob/master/ext/puma_http11/mini_ssl.c
#define RSTRING_NOT_MODIFIED 1
#include <assert.h>
#include <ruby.h>
#include <rubyio.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct {
  BIO* read;
  BIO* write;
  SSL* ssl;
  SSL_CTX* ctx;
} ms_conn;

void engine_free(ms_conn* conn) {
  BIO_free(conn->read);
  BIO_free(conn->write);

  free(conn);
}

static VALUE eError;

void raise_error(SSL* ssl, int result) {
  char buf[256];
  u_long err;

  while ((err = ERR_get_error()) != 0) {
    ERR_error_string_n(err, buf, sizeof(buf));
    printf("*** %s\n", buf);
  }

  ERR_clear_error();
  rb_raise(eError, "OpenSSL error");
}

ms_conn* engine_alloc(VALUE klass, VALUE* obj) {
  ms_conn* conn;

  *obj = Data_Make_Struct(klass, ms_conn, 0, engine_free, conn);

  conn->read = BIO_new(BIO_s_mem());
  BIO_set_nbio(conn->read, 1);

  conn->write = BIO_new(BIO_s_mem());
  BIO_set_nbio(conn->write, 1);

  conn->ssl = 0;
  conn->ctx = 0;

  return conn;
}

VALUE engine_init_server(VALUE self, VALUE key, VALUE cert) {
  VALUE obj;
  SSL_CTX* ctx;
  SSL* ssl;
  int use_certificate_file_ret, use_pk_file_ret;

  ms_conn* conn = engine_alloc(self, &obj);

  StringValue(key);
  StringValue(cert);

  ctx = SSL_CTX_new(TLSv1_server_method());
  conn->ctx = ctx;

  use_certificate_file_ret = SSL_CTX_use_certificate_file(ctx, RSTRING_PTR(cert), SSL_FILETYPE_PEM);
  if(use_certificate_file_ret != 1) {
    raise_error(conn->ssl, 0);
  }

  use_pk_file_ret = SSL_CTX_use_PrivateKey_file(ctx, RSTRING_PTR(key), SSL_FILETYPE_PEM);
  if(use_pk_file_ret != 1) {
    raise_error(conn->ssl, 0);
  }

  SSL_CTX_set_cipher_list(ctx, "ALL");
  SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);

  ssl = SSL_new(ctx);
  conn->ssl = ssl;

  SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

  SSL_set_bio(conn->ssl, conn->read, conn->write);

  SSL_set_accept_state(ssl);
  return obj;
}

VALUE engine_init_client(VALUE klass) {
  VALUE obj;
  ms_conn* conn = engine_alloc(klass, &obj);

  conn->ctx = SSL_CTX_new(TLSv1_client_method());
  SSL_CTX_set_cipher_list(conn->ctx, "ALL");

  conn->ssl = SSL_new(conn->ctx);

  SSL_set_verify(conn->ssl, SSL_VERIFY_NONE, NULL);

  SSL_set_bio(conn->ssl, conn->read, conn->write);

  SSL_set_connect_state(conn->ssl);
  return obj;
}

VALUE engine_inject(VALUE self, VALUE str) {
  ms_conn* conn;
  long used;

  Data_Get_Struct(self, ms_conn, conn);

  StringValue(str);

  used = BIO_write(conn->read, RSTRING_PTR(str), (int)RSTRING_LEN(str));

  if(used == 0 || used == -1) {
    return Qfalse;
  }

  return INT2FIX(used);
}

VALUE engine_read(VALUE self) {
  ms_conn* conn;
  char buf[512];
  int bytes, n;

  Data_Get_Struct(self, ms_conn, conn);

  bytes = SSL_read(conn->ssl, (void*)buf, sizeof(buf));

  if(bytes > 0) {
    return rb_str_new(buf, bytes);
  }

  if(SSL_want_read(conn->ssl)) return Qnil;

  if(SSL_get_error(conn->ssl, bytes) == SSL_ERROR_ZERO_RETURN) {
    rb_eof_error();
  }

  raise_error(conn->ssl, bytes);

  return Qnil;
}

VALUE engine_write(VALUE self, VALUE str) {
  ms_conn* conn;
  char buf[512];
  int bytes;

  Data_Get_Struct(self, ms_conn, conn);

  StringValue(str);

  bytes = SSL_write(conn->ssl, (void*)RSTRING_PTR(str), (int)RSTRING_LEN(str));
  if(bytes > 0) {
    return INT2FIX(bytes);
  }

  if(SSL_want_write(conn->ssl)) return Qnil;

  raise_error(conn->ssl, bytes);

  return Qnil;
}

VALUE engine_extract(VALUE self) {
  ms_conn* conn;
  int bytes;
  size_t pending;
  char buf[512];

  Data_Get_Struct(self, ms_conn, conn);

  pending = BIO_pending(conn->write);
  if(pending > 0) {
    bytes = BIO_read(conn->write, buf, sizeof(buf));
    if(bytes > 0) {
      return rb_str_new(buf, bytes);
    } else if(!BIO_should_retry(conn->write)) {
      raise_error(conn->ssl, bytes);
    }
  }

  return Qnil;
}

void Init_engine() {
  VALUE mod, eng, rack;
  
  SSL_library_init();
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();
  ERR_load_crypto_strings();

  rack = rb_define_module("Rack");
  mod = rb_define_class_under(rack, "TCTP", rb_cObject);
  eng = rb_define_class_under(mod, "Engine", rb_cObject);

  eError = rb_define_class_under(mod, "SSLError", rb_eStandardError);

  rb_define_singleton_method(eng, "server", engine_init_server, 2);
  rb_define_singleton_method(eng, "client", engine_init_client, 0);

  rb_define_method(eng, "inject", engine_inject, 1);
  rb_define_method(eng, "read",  engine_read, 0);

  rb_define_method(eng, "write",  engine_write, 1);
  rb_define_method(eng, "extract", engine_extract, 0);
}

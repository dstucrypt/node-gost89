#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include "string.h"

extern "C" {
#include "gost89.h"
#include "gosthash.h"
#include "sbox.h"
#include "hash.h"
}

using namespace v8;
using namespace node;

Handle<Value> HashUpdate(const Arguments &args) {
    HandleScope scope;
    if (!Buffer::HasInstance(args[0])) {
        return ThrowException(Exception::TypeError(String::New(
            "First argument must be a Buffer")));
    }
    Local<Object> buf = args[0]->ToObject();
    size_t length = Buffer::Length(buf);
    byte *data = (byte *)Buffer::Data(buf);

    Local<Object> self = args.Holder();
    Local<External> wrap = Local<External>::Cast(self->GetInternalField(0));
    gost_hash_ctx *hash_ctx = (gost_hash_ctx*)wrap->Value();
    int err = hash_block(hash_ctx, data, length);
    if(err != 1) {
        return ThrowException(Exception::TypeError(String::New(
            "Internal error in gost89 hashing")));
    }

    return scope.Close(Undefined());
}

Handle<Value> HashFinish(const Arguments &args) {
    HandleScope scope;
    if (!Buffer::HasInstance(args[0])) {
        return ThrowException(Exception::TypeError(String::New(
            "First argument must be a Buffer")));
    }
    Local<Object> buf = args[0]->ToObject();
    size_t length = Buffer::Length(buf);
    if (length != 32) {
        return ThrowException(Exception::TypeError(String::New(
            "First argument must be a Buffer of 32 bytes")));
    }
    byte *data = (byte *)Buffer::Data(buf);

    Local<Object> self = args.Holder();
    Local<External> wrap = Local<External>::Cast(self->GetInternalField(0));
    gost_hash_ctx *hash_ctx = (gost_hash_ctx*)wrap->Value();
    int err = finish_hash(hash_ctx, data);
    done_gost_hash_ctx(hash_ctx);
    free(hash_ctx);
    self->SetInternalField(0, Undefined());

    if(err != 1) {
        return ThrowException(Exception::TypeError(String::New(
            "Internal error in gost89 hashing")));
    }

    return scope.Close(Undefined());
}

Handle<Value> HashInit(const Arguments &args) {
    HandleScope scope;

    gost_hash_ctx *hash_ctx = (gost_hash_ctx *)malloc(sizeof (gost_hash_ctx));
    gost_subst_block sbox;
    unpack_sbox(default_sbox, &sbox);
    memset(hash_ctx, 0, sizeof(gost_hash_ctx));

    int err = init_gost_hash_ctx(hash_ctx, &sbox);
    if (err != 1) {
        return ThrowException(Exception::TypeError(String::New(
            "Second argument must be a Buffer of 32 bytes")));
    }

    Local<ObjectTemplate> point_templ = ObjectTemplate::New();
    point_templ->SetInternalFieldCount(1);
    Local<Object> obj = point_templ->NewInstance();

    obj->Set(String::NewSymbol("update"),
            FunctionTemplate::New(HashUpdate)->GetFunction());

    obj->Set(String::NewSymbol("finish"),
            FunctionTemplate::New(HashFinish)->GetFunction());

    obj->SetInternalField(0, External::New(hash_ctx));

    return scope.Close(obj);
}

Handle<Value> GostHash(const Arguments &args) {
  HandleScope scope;
  if (!Buffer::HasInstance(args[0])) {
    return ThrowException(Exception::TypeError(String::New(
            "First argument must be a Buffer")));
  }

  if (!Buffer::HasInstance(args[1])) {
    return ThrowException(Exception::TypeError(String::New(
            "Second argument must be a Buffer")));
  }

  Local<Object> buf = args[0]->ToObject();
  Local<Object> hbuf = args[1]->ToObject();

  if (Buffer::Length(hbuf) != 32) {
    return ThrowException(Exception::TypeError(String::New(
            "Second argument must be a Buffer of 32 bytes")));

  }

  byte *data = (byte *)Buffer::Data(buf);
  size_t length = Buffer::Length(buf);

  byte *out = (byte *)Buffer::Data(hbuf);

  length = compute_hash((const byte*)data, length, out);

  return scope.Close(Integer::NewFromUnsigned(length));
}

extern "C"
void init(Handle<Object> target) {
  HandleScope scope;
  target->Set(String::NewSymbol("gosthash"),
          FunctionTemplate::New(GostHash)->GetFunction());
  target->Set(String::NewSymbol("hashinit"),
          FunctionTemplate::New(HashInit)->GetFunction());

}
NODE_MODULE(binding, init)

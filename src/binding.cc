#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include "string.h"

extern "C" {
#include "gost89.h"
#include "sbox.h"
#include "gosthash.h"
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
    if(err != 1) {
        return ThrowException(Exception::TypeError(String::New(
            "Internal error in gost89 hashing")));
    }

    return scope.Close(Undefined());
}

Handle<Value> HashReset(const Arguments &args) {
    HandleScope scope;
    Local<Object> self = args.Holder();
    Local<External> wrap = Local<External>::Cast(self->GetInternalField(0));
    gost_hash_ctx *hash_ctx = (gost_hash_ctx*)wrap->Value();
    int err = start_hash(hash_ctx);
    if(err != 1) {
        return ThrowException(Exception::TypeError(String::New(
            "Internal error in gost89 hashing")));
    }

    return scope.Close(Undefined());
}

void gost_hash_free_cb(Persistent<Value> object, void *parameter) {
    gost_hash_ctx *hash_ctx = (gost_hash_ctx *)parameter;
    done_gost_hash_ctx(hash_ctx);
    free(hash_ctx);
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
    Persistent<Object> obj = Persistent<Object>::New(point_templ->NewInstance());

    obj->Set(String::NewSymbol("update"),
            FunctionTemplate::New(HashUpdate)->GetFunction());

    obj->Set(String::NewSymbol("finish"),
            FunctionTemplate::New(HashFinish)->GetFunction());

    obj->Set(String::NewSymbol("reset"),
            FunctionTemplate::New(HashReset)->GetFunction());

    obj->SetInternalField(0, External::New(hash_ctx));

    obj.MakeWeak(hash_ctx, gost_hash_free_cb);

    return scope.Close(obj);
}

Handle<Value> GostDone(const Arguments &args) {
    HandleScope scope;
    Local<Object> self = args.Holder();
    Local<External> wrap = Local<External>::Cast(self->GetInternalField(0));
    gost_ctx *ctx = (gost_ctx*)wrap->Value();
    gost_destroy(ctx);

    return scope.Close(Undefined());
}

Handle<Value> GostKey(const Arguments &args) {
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
    gost_ctx *ctx = (gost_ctx*)wrap->Value();
    gost_key(ctx, data);

    return scope.Close(Undefined());
}

Handle<Value> GostCrypt(const Arguments &args) {
    HandleScope scope;
    int64_t op;

    if (!Buffer::HasInstance(args[0])) {
        return ThrowException(Exception::TypeError(String::New(
            "First argument must be a Buffer")));
    }
    if (!Buffer::HasInstance(args[1])) {
        return ThrowException(Exception::TypeError(String::New(
            "Second argument must be a Buffer")));
    }
    if (!args[2]->IsInt32()) {
        return ThrowException(Exception::TypeError(String::New(
            "Third argument must be an Integer")));
    }
    Local<Integer> mode = Local<Integer>::Cast(args[2]);

    op = mode->Value();

    size_t length;
    byte *iv = NULL;

    if(op == 2 || op == 3) {
        Local<Object>ivbuf;
        if (!Buffer::HasInstance(args[3])) {
            return ThrowException(Exception::TypeError(String::New(
            "Fourth argument must be a Buffer")));
        }
        ivbuf = args[3]->ToObject();
        if (Buffer::Length(ivbuf) != 8) {
            return ThrowException(Exception::TypeError(String::New(
                "Fourth argument must be a Buffer of 8 bytes")));

        }
        iv = (byte *)Buffer::Data(ivbuf);
    }

    Local<Object> buf = args[0]->ToObject();
    Local<Object> obuf = args[1]->ToObject();

    length = Buffer::Length(buf);
    size_t out_length = Buffer::Length(obuf);
    if (length != out_length) {
        return ThrowException(Exception::TypeError(String::New(
            "Buffers should have equal size"
        )));
    }
    byte *data = (byte *)Buffer::Data(buf);
    byte *odata = (byte *)Buffer::Data(obuf);

    Local<Object> self = args.Holder();
    Local<External> wrap = Local<External>::Cast(self->GetInternalField(0));
    gost_ctx *ctx = (gost_ctx*)wrap->Value();
    length = (length+7) / 8;

    switch (op) {
    case 0:
        gost_enc(ctx, data, odata, length);
        break;
    case 1:
        gost_dec(ctx, data, odata, length);
        break;
    case 2:
        gost_enc_cfb(ctx, iv, data, odata, length);
        break;
    case 3:
        gost_dec_cfb(ctx, iv, data, odata, length);
    };

    return scope.Close(Undefined());
}

Handle<Value> GostMac(const Arguments &args) {
    HandleScope scope;

    if (!Buffer::HasInstance(args[0])) {
        return ThrowException(Exception::TypeError(String::New(
            "First argument must be a Buffer")));
    }
    if (!Buffer::HasInstance(args[1])) {
        return ThrowException(Exception::TypeError(String::New(
            "Second argument must be a Buffer")));
    }
    if (!args[2]->IsInt32()) {
        return ThrowException(Exception::TypeError(String::New(
            "Third argument must be an Integer")));
    }
    Local<Object> buf = args[0]->ToObject();
    Local<Object> obuf = args[1]->ToObject();
    Local<Integer> lbits = Local<Integer>::Cast(args[2]);

    int bits = lbits->Value();
    int length = Buffer::Length(buf);
    int mac_length = Buffer::Length(obuf);
    if (mac_length * 8 != bits) {
        return ThrowException(Exception::TypeError(String::New(
            "Output buffer should be equal to requested mac size"
        )));
    }
    byte *data = (byte *)Buffer::Data(buf);
    byte *odata = (byte *)Buffer::Data(obuf);

    Local<Object> self = args.Holder();
    Local<External> wrap = Local<External>::Cast(self->GetInternalField(0));
    gost_ctx *ctx = (gost_ctx*)wrap->Value();
    gost_mac(ctx, bits, data, length, odata);

    return scope.Close(Undefined());
}

void gost_free_cb(Persistent<Value> object, void *parameter) {
    gost_ctx *ctx = (gost_ctx *)parameter;
    gost_destroy(ctx);
    free(ctx);
}

Handle<Value> Init(const Arguments &args) {
    HandleScope scope;

    gost_ctx *ctx = (gost_ctx *)malloc(sizeof (gost_ctx));
    gost_subst_block sbox;
    unpack_sbox(default_sbox, &sbox);
    memset(ctx, 0, sizeof(gost_ctx));

    gost_init(ctx, &sbox);

    Local<ObjectTemplate> point_templ = ObjectTemplate::New();
    point_templ->SetInternalFieldCount(1);
    Persistent<Object> obj = Persistent<Object>::New(point_templ->NewInstance());

    obj->Set(String::NewSymbol("key"),
            FunctionTemplate::New(GostKey)->GetFunction());

    obj->Set(String::NewSymbol("done"),
            FunctionTemplate::New(GostDone)->GetFunction());

    obj->Set(String::NewSymbol("crypt"),
            FunctionTemplate::New(GostCrypt)->GetFunction());

    obj->Set(String::NewSymbol("mac"),
            FunctionTemplate::New(GostMac)->GetFunction());

    obj->SetInternalField(0, External::New(ctx));

    obj.MakeWeak(ctx, gost_free_cb);

    return scope.Close(obj);
}

extern "C"
void init(Handle<Object> target) {
  HandleScope scope;
  target->Set(String::NewSymbol("hashinit"),
          FunctionTemplate::New(HashInit)->GetFunction());
  target->Set(String::NewSymbol("init"),
          FunctionTemplate::New(Init)->GetFunction());

}
NODE_MODULE(binding, init)

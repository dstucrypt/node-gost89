#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include "string.h"
#include "gost89.h"
#include "hash.h"

using namespace v8;
using namespace node;

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
}
NODE_MODULE(binding, init)

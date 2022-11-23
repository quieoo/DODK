// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: grpc_orchestrator.proto

#include "grpc_orchestrator.pb.h"
#include "grpc_orchestrator.grpc.pb.h"

#include <functional>
#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/channel_interface.h>
#include <grpcpp/impl/codegen/client_unary_call.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/message_allocator.h>
#include <grpcpp/impl/codegen/method_handler.h>
#include <grpcpp/impl/codegen/rpc_service_method.h>
#include <grpcpp/impl/codegen/server_callback.h>
#include <grpcpp/impl/codegen/server_callback_handlers.h>
#include <grpcpp/impl/codegen/server_context.h>
#include <grpcpp/impl/codegen/service_type.h>
#include <grpcpp/impl/codegen/sync_stream.h>
namespace orchestaror {

static const char* Orchestrator_method_names[] = {
  "/orchestaror.Orchestrator/GetProgramList",
  "/orchestaror.Orchestrator/Create",
  "/orchestaror.Orchestrator/Destroy",
  "/orchestaror.Orchestrator/Create_Attach",
};

std::unique_ptr< Orchestrator::Stub> Orchestrator::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< Orchestrator::Stub> stub(new Orchestrator::Stub(channel, options));
  return stub;
}

Orchestrator::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options)
  : channel_(channel), rpcmethod_GetProgramList_(Orchestrator_method_names[0], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_Create_(Orchestrator_method_names[1], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_Destroy_(Orchestrator_method_names[2], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_Create_Attach_(Orchestrator_method_names[3], options.suffix_for_stats(),::grpc::internal::RpcMethod::SERVER_STREAMING, channel)
  {}

::grpc::Status Orchestrator::Stub::GetProgramList(::grpc::ClientContext* context, const ::orchestaror::ProgramListReq& request, ::orchestaror::ProgramList* response) {
  return ::grpc::internal::BlockingUnaryCall< ::orchestaror::ProgramListReq, ::orchestaror::ProgramList, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_GetProgramList_, context, request, response);
}

void Orchestrator::Stub::async::GetProgramList(::grpc::ClientContext* context, const ::orchestaror::ProgramListReq* request, ::orchestaror::ProgramList* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::orchestaror::ProgramListReq, ::orchestaror::ProgramList, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_GetProgramList_, context, request, response, std::move(f));
}

void Orchestrator::Stub::async::GetProgramList(::grpc::ClientContext* context, const ::orchestaror::ProgramListReq* request, ::orchestaror::ProgramList* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_GetProgramList_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::orchestaror::ProgramList>* Orchestrator::Stub::PrepareAsyncGetProgramListRaw(::grpc::ClientContext* context, const ::orchestaror::ProgramListReq& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::orchestaror::ProgramList, ::orchestaror::ProgramListReq, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_GetProgramList_, context, request);
}

::grpc::ClientAsyncResponseReader< ::orchestaror::ProgramList>* Orchestrator::Stub::AsyncGetProgramListRaw(::grpc::ClientContext* context, const ::orchestaror::ProgramListReq& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncGetProgramListRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status Orchestrator::Stub::Create(::grpc::ClientContext* context, const ::orchestaror::CMD& request, ::orchestaror::RichStatus* response) {
  return ::grpc::internal::BlockingUnaryCall< ::orchestaror::CMD, ::orchestaror::RichStatus, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_Create_, context, request, response);
}

void Orchestrator::Stub::async::Create(::grpc::ClientContext* context, const ::orchestaror::CMD* request, ::orchestaror::RichStatus* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::orchestaror::CMD, ::orchestaror::RichStatus, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Create_, context, request, response, std::move(f));
}

void Orchestrator::Stub::async::Create(::grpc::ClientContext* context, const ::orchestaror::CMD* request, ::orchestaror::RichStatus* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Create_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::orchestaror::RichStatus>* Orchestrator::Stub::PrepareAsyncCreateRaw(::grpc::ClientContext* context, const ::orchestaror::CMD& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::orchestaror::RichStatus, ::orchestaror::CMD, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_Create_, context, request);
}

::grpc::ClientAsyncResponseReader< ::orchestaror::RichStatus>* Orchestrator::Stub::AsyncCreateRaw(::grpc::ClientContext* context, const ::orchestaror::CMD& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncCreateRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status Orchestrator::Stub::Destroy(::grpc::ClientContext* context, const ::orchestaror::Uid& request, ::orchestaror::Status* response) {
  return ::grpc::internal::BlockingUnaryCall< ::orchestaror::Uid, ::orchestaror::Status, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_Destroy_, context, request, response);
}

void Orchestrator::Stub::async::Destroy(::grpc::ClientContext* context, const ::orchestaror::Uid* request, ::orchestaror::Status* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::orchestaror::Uid, ::orchestaror::Status, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Destroy_, context, request, response, std::move(f));
}

void Orchestrator::Stub::async::Destroy(::grpc::ClientContext* context, const ::orchestaror::Uid* request, ::orchestaror::Status* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Destroy_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::orchestaror::Status>* Orchestrator::Stub::PrepareAsyncDestroyRaw(::grpc::ClientContext* context, const ::orchestaror::Uid& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::orchestaror::Status, ::orchestaror::Uid, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_Destroy_, context, request);
}

::grpc::ClientAsyncResponseReader< ::orchestaror::Status>* Orchestrator::Stub::AsyncDestroyRaw(::grpc::ClientContext* context, const ::orchestaror::Uid& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncDestroyRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::ClientReader< ::orchestaror::Reply>* Orchestrator::Stub::Create_AttachRaw(::grpc::ClientContext* context, const ::orchestaror::CMD& request) {
  return ::grpc::internal::ClientReaderFactory< ::orchestaror::Reply>::Create(channel_.get(), rpcmethod_Create_Attach_, context, request);
}

void Orchestrator::Stub::async::Create_Attach(::grpc::ClientContext* context, const ::orchestaror::CMD* request, ::grpc::ClientReadReactor< ::orchestaror::Reply>* reactor) {
  ::grpc::internal::ClientCallbackReaderFactory< ::orchestaror::Reply>::Create(stub_->channel_.get(), stub_->rpcmethod_Create_Attach_, context, request, reactor);
}

::grpc::ClientAsyncReader< ::orchestaror::Reply>* Orchestrator::Stub::AsyncCreate_AttachRaw(::grpc::ClientContext* context, const ::orchestaror::CMD& request, ::grpc::CompletionQueue* cq, void* tag) {
  return ::grpc::internal::ClientAsyncReaderFactory< ::orchestaror::Reply>::Create(channel_.get(), cq, rpcmethod_Create_Attach_, context, request, true, tag);
}

::grpc::ClientAsyncReader< ::orchestaror::Reply>* Orchestrator::Stub::PrepareAsyncCreate_AttachRaw(::grpc::ClientContext* context, const ::orchestaror::CMD& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncReaderFactory< ::orchestaror::Reply>::Create(channel_.get(), cq, rpcmethod_Create_Attach_, context, request, false, nullptr);
}

Orchestrator::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      Orchestrator_method_names[0],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< Orchestrator::Service, ::orchestaror::ProgramListReq, ::orchestaror::ProgramList, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](Orchestrator::Service* service,
             ::grpc::ServerContext* ctx,
             const ::orchestaror::ProgramListReq* req,
             ::orchestaror::ProgramList* resp) {
               return service->GetProgramList(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      Orchestrator_method_names[1],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< Orchestrator::Service, ::orchestaror::CMD, ::orchestaror::RichStatus, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](Orchestrator::Service* service,
             ::grpc::ServerContext* ctx,
             const ::orchestaror::CMD* req,
             ::orchestaror::RichStatus* resp) {
               return service->Create(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      Orchestrator_method_names[2],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< Orchestrator::Service, ::orchestaror::Uid, ::orchestaror::Status, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](Orchestrator::Service* service,
             ::grpc::ServerContext* ctx,
             const ::orchestaror::Uid* req,
             ::orchestaror::Status* resp) {
               return service->Destroy(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      Orchestrator_method_names[3],
      ::grpc::internal::RpcMethod::SERVER_STREAMING,
      new ::grpc::internal::ServerStreamingHandler< Orchestrator::Service, ::orchestaror::CMD, ::orchestaror::Reply>(
          [](Orchestrator::Service* service,
             ::grpc::ServerContext* ctx,
             const ::orchestaror::CMD* req,
             ::grpc::ServerWriter<::orchestaror::Reply>* writer) {
               return service->Create_Attach(ctx, req, writer);
             }, this)));
}

Orchestrator::Service::~Service() {
}

::grpc::Status Orchestrator::Service::GetProgramList(::grpc::ServerContext* context, const ::orchestaror::ProgramListReq* request, ::orchestaror::ProgramList* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status Orchestrator::Service::Create(::grpc::ServerContext* context, const ::orchestaror::CMD* request, ::orchestaror::RichStatus* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status Orchestrator::Service::Destroy(::grpc::ServerContext* context, const ::orchestaror::Uid* request, ::orchestaror::Status* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status Orchestrator::Service::Create_Attach(::grpc::ServerContext* context, const ::orchestaror::CMD* request, ::grpc::ServerWriter< ::orchestaror::Reply>* writer) {
  (void) context;
  (void) request;
  (void) writer;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace orchestaror

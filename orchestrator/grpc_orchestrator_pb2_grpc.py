# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import grpc_orchestrator_pb2 as grpc__orchestrator__pb2


class OrchestratorStub(object):
    """Host (x86) -> DPU (Arm):
    ========================
    gRPC server that exposes the gRPC API to the host
    for remote boot/shutdown of gRPC Programs.
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.GetProgramList = channel.unary_unary(
                '/Orchestrator/GetProgramList',
                request_serializer=grpc__orchestrator__pb2.ProgramListReq.SerializeToString,
                response_deserializer=grpc__orchestrator__pb2.ProgramList.FromString,
                )
        self.Create = channel.unary_unary(
                '/Orchestrator/Create',
                request_serializer=grpc__orchestrator__pb2.CMD.SerializeToString,
                response_deserializer=grpc__orchestrator__pb2.RichStatus.FromString,
                )
        self.Destroy = channel.unary_unary(
                '/Orchestrator/Destroy',
                request_serializer=grpc__orchestrator__pb2.Uid.SerializeToString,
                response_deserializer=grpc__orchestrator__pb2.Status.FromString,
                )
        self.Create_Attach = channel.unary_stream(
                '/Orchestrator/Create_Attach',
                request_serializer=grpc__orchestrator__pb2.CMD.SerializeToString,
                response_deserializer=grpc__orchestrator__pb2.Reply.FromString,
                )


class OrchestratorServicer(object):
    """Host (x86) -> DPU (Arm):
    ========================
    gRPC server that exposes the gRPC API to the host
    for remote boot/shutdown of gRPC Programs.
    """

    def GetProgramList(self, request, context):
        """Fetch the list of gRPC-Supported Programs 
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Create(self, request, context):
        """Invoke a given gRPC-Supported program 
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Destroy(self, request, context):
        """Destroy a given gRPC-Supported program 
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Create_Attach(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_OrchestratorServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'GetProgramList': grpc.unary_unary_rpc_method_handler(
                    servicer.GetProgramList,
                    request_deserializer=grpc__orchestrator__pb2.ProgramListReq.FromString,
                    response_serializer=grpc__orchestrator__pb2.ProgramList.SerializeToString,
            ),
            'Create': grpc.unary_unary_rpc_method_handler(
                    servicer.Create,
                    request_deserializer=grpc__orchestrator__pb2.CMD.FromString,
                    response_serializer=grpc__orchestrator__pb2.RichStatus.SerializeToString,
            ),
            'Destroy': grpc.unary_unary_rpc_method_handler(
                    servicer.Destroy,
                    request_deserializer=grpc__orchestrator__pb2.Uid.FromString,
                    response_serializer=grpc__orchestrator__pb2.Status.SerializeToString,
            ),
            'Create_Attach': grpc.unary_stream_rpc_method_handler(
                    servicer.Create_Attach,
                    request_deserializer=grpc__orchestrator__pb2.CMD.FromString,
                    response_serializer=grpc__orchestrator__pb2.Reply.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'Orchestrator', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class Orchestrator(object):
    """Host (x86) -> DPU (Arm):
    ========================
    gRPC server that exposes the gRPC API to the host
    for remote boot/shutdown of gRPC Programs.
    """

    @staticmethod
    def GetProgramList(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/Orchestrator/GetProgramList',
            grpc__orchestrator__pb2.ProgramListReq.SerializeToString,
            grpc__orchestrator__pb2.ProgramList.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Create(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/Orchestrator/Create',
            grpc__orchestrator__pb2.CMD.SerializeToString,
            grpc__orchestrator__pb2.RichStatus.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Destroy(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/Orchestrator/Destroy',
            grpc__orchestrator__pb2.Uid.SerializeToString,
            grpc__orchestrator__pb2.Status.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Create_Attach(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_stream(request, target, '/Orchestrator/Create_Attach',
            grpc__orchestrator__pb2.CMD.SerializeToString,
            grpc__orchestrator__pb2.Reply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

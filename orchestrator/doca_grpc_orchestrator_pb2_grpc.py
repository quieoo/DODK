# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import doca_grpc_orchestrator_pb2 as doca__grpc__orchestrator__pb2


class DocaOrchestratorStub(object):
    """Host (x86) -> DPU (Arm):
    ========================
    gRPC server that exposes the DOCA gRPC API to the host
    for remote boot/shutdown of DOCA gRPC Programs.
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.GetProgramList = channel.unary_unary(
                '/DocaOrchestrator/GetProgramList',
                request_serializer=doca__grpc__orchestrator__pb2.ProgramListReq.SerializeToString,
                response_deserializer=doca__grpc__orchestrator__pb2.ProgramList.FromString,
                )
        self.Create = channel.unary_unary(
                '/DocaOrchestrator/Create',
                request_serializer=doca__grpc__orchestrator__pb2.Args.SerializeToString,
                response_deserializer=doca__grpc__orchestrator__pb2.RichStatus.FromString,
                )
        self.Destroy = channel.unary_unary(
                '/DocaOrchestrator/Destroy',
                request_serializer=doca__grpc__orchestrator__pb2.Uid.SerializeToString,
                response_deserializer=doca__grpc__orchestrator__pb2.Status.FromString,
                )


class DocaOrchestratorServicer(object):
    """Host (x86) -> DPU (Arm):
    ========================
    gRPC server that exposes the DOCA gRPC API to the host
    for remote boot/shutdown of DOCA gRPC Programs.
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


def add_DocaOrchestratorServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'GetProgramList': grpc.unary_unary_rpc_method_handler(
                    servicer.GetProgramList,
                    request_deserializer=doca__grpc__orchestrator__pb2.ProgramListReq.FromString,
                    response_serializer=doca__grpc__orchestrator__pb2.ProgramList.SerializeToString,
            ),
            'Create': grpc.unary_unary_rpc_method_handler(
                    servicer.Create,
                    request_deserializer=doca__grpc__orchestrator__pb2.Args.FromString,
                    response_serializer=doca__grpc__orchestrator__pb2.RichStatus.SerializeToString,
            ),
            'Destroy': grpc.unary_unary_rpc_method_handler(
                    servicer.Destroy,
                    request_deserializer=doca__grpc__orchestrator__pb2.Uid.FromString,
                    response_serializer=doca__grpc__orchestrator__pb2.Status.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'DocaOrchestrator', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class DocaOrchestrator(object):
    """Host (x86) -> DPU (Arm):
    ========================
    gRPC server that exposes the DOCA gRPC API to the host
    for remote boot/shutdown of DOCA gRPC Programs.
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
        return grpc.experimental.unary_unary(request, target, '/DocaOrchestrator/GetProgramList',
            doca__grpc__orchestrator__pb2.ProgramListReq.SerializeToString,
            doca__grpc__orchestrator__pb2.ProgramList.FromString,
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
        return grpc.experimental.unary_unary(request, target, '/DocaOrchestrator/Create',
            doca__grpc__orchestrator__pb2.Args.SerializeToString,
            doca__grpc__orchestrator__pb2.RichStatus.FromString,
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
        return grpc.experimental.unary_unary(request, target, '/DocaOrchestrator/Destroy',
            doca__grpc__orchestrator__pb2.Uid.SerializeToString,
            doca__grpc__orchestrator__pb2.Status.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
